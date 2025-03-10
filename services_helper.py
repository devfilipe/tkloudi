import os
import re
import traceback


def find_closing_bracket(text, start_pos, open_char, close_char):
    count = 0
    for i in range(start_pos, len(text)):
        if text[i] == open_char:
            count += 1
        elif text[i] == close_char:
            count -= 1
            if count == 0:
                return i
    return -1


def extract_service_entries(content):
    entries = []
    i = 0
    in_comment = False
    while i < len(content):
        if content[i : i + 2] == "%":
            while i < len(content) and content[i] != "\n":
                i += 1
            i += 1
            continue
        elif content[i : i + 2] == "/*":
            in_comment = True
            i += 2
            continue
        elif in_comment and content[i : i + 2] == "*/":
            in_comment = False
            i += 2
            continue
        elif in_comment:
            i += 1
            continue
        if content[i] == "[":
            start_pos = i
            end_pos = find_closing_bracket(content, start_pos, "[", "]")
            if end_pos != -1:
                entry = content[start_pos : end_pos + 1]
                entries.append(entry)
                i = end_pos + 1
            else:
                i += 1
        else:
            i += 1
    return entries


def parse_service_entry(entry):
    service = {}
    service["original_entry"] = entry.strip()
    prefix_match = re.search(r'\{prefix,\s*[\'"]?([^\'",}\s]+)[\'"]?', entry)
    if prefix_match:
        service["prefix"] = prefix_match.group(1)
    type_match = re.search(r"\{type,\s*([^},\s]+)", entry)
    if type_match:
        service["type"] = type_match.group(1).strip()
    else:
        service["type"] = "external"
    module_match = re.search(r"\{module,\s*([^},\s]+)", entry)
    if module_match:
        service["module"] = module_match.group(1).strip()
    file_path_match = re.search(r'\{file_path,\s*[\'"]([^\'"]+)[\'"]', entry)
    if file_path_match:
        service["file_path"] = file_path_match.group(1)
    args_match = re.search(r"\{args,\s*([^}]+)\}", entry)
    if args_match:
        service["args"] = args_match.group(1).strip()
    if "module" in service:
        service["label"] = service["module"]
    elif "file_path" in service:
        filename = os.path.basename(service["file_path"])
        if "args" in service:
            service["label"] = f"{filename} {service['args']}"
        else:
            service["label"] = filename
    else:
        service["label"] = f"Service: {service.get('prefix', 'unknown')}"
    return service


def extract_services_direct(content, filepath):
    services = []
    try:
        service_blocks = re.findall(
            r"\[([\s\S]*?prefix[\s\S]*?(module|file_path)[\s\S]*?)\]", content
        )
        for block_match in service_blocks:
            block = f"[{block_match[0]}]"
            service = parse_service_entry(block)
            if (
                service
                and "prefix" in service
                and ("module" in service or "file_path" in service)
            ):
                services.append(service)
    except Exception as e:
        # print(f"Error in direct extraction: {str(e)}")
        traceback.print_exc()
    return services


def parse_services(content, filepath):
    services = []
    patterns = [
        "{services, [",
        "{services,[",
        "services, [",
        "services,[",
    ]
    start = -1
    for pattern in patterns:
        pos = content.find(pattern)
        if pos != -1:
            start = pos + len(pattern)
            break
    if start == -1:
        service_entries = extract_service_entries(content)
        if service_entries:
            for entry in service_entries:
                service = parse_service_entry(entry)
                if service:
                    services.append(service)
            return services
        else:
            return []
    services_content = content[start:]
    end = find_closing_bracket(services_content, 0, "[", "]")
    if end == -1:
        return []
    services_content = services_content[:end]
    service_entries = extract_service_entries(services_content)
    if not service_entries:
        service_patterns = re.findall(
            r"\[[^]]*?prefix[^]]*?(module|file_path)[^]]*?\]", services_content
        )
        if service_patterns:
            for match in service_patterns:
                entry = match
                service = parse_service_entry(entry)
                if service:
                    services.append(service)
    else:
        for entry in service_entries:
            service = parse_service_entry(entry)
            if service:
                services.append(service)
    return services


def parse_erlang_response(text):
    status_data = []
    try:
        text = re.sub(r"\s+", " ", text.strip())

        i = 0
        while i < len(text):
            uuid_start = text.find('{"', i)
            if uuid_start == -1:
                break

            uuid_end = text.find('",', uuid_start)
            if uuid_end == -1:
                break

            uuid = text[uuid_start + 2 : uuid_end]

            bracket_start = text.find("[", uuid_end)
            if bracket_start == -1:
                break

            bracket_end = find_closing_bracket(text, bracket_start, "[", "]")
            if bracket_end == -1:
                break

            entry_content = text[bracket_start + 1 : bracket_end]

            service_info = {"uuid": uuid, "key": uuid}

            module_match = re.search(r"\{module,([^{}]+?)\}", entry_content)
            if module_match:
                service_info["module"] = module_match.group(1).strip()

            file_path_match = re.search(r'\{file_path,\s*"([^"]+)"\}', entry_content)
            if file_path_match:
                service_info["file_path"] = file_path_match.group(1)

            prefix_match = re.search(r'\{prefix,\s*"([^"]+)"\}', entry_content)
            if prefix_match:
                service_info["prefix"] = prefix_match.group(1)

            type_match = re.search(r"\{type,([^{}]+?)\}", entry_content)
            if type_match:
                service_info["type"] = type_match.group(1).strip()

            suspended_match = re.search(r"\{suspended\s*,\s*true\}", entry_content)
            service_info["suspended"] = suspended_match is not None

            args_match = re.search(r"\{args,([^{}]+?)\}", entry_content)
            if args_match:
                service_info["args"] = args_match.group(1).strip()

            if (
                "prefix" in service_info
                or "module" in service_info
                or "file_path" in service_info
            ):
                status_data.append(service_info)

            i = bracket_end + 1

        return status_data

    except Exception as e:
        # print(f"Error parsing Erlang response: {str(e)}")
        traceback.print_exc()
        return []
