import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import json
import os


class RPCFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.api_data = []

        if hasattr(master, "config_data"):
            self.config = master.config_data
        else:
            self.config = self.load_config()

        self.create_widgets()

    def load_config(self):
        config_path = "files/api.conf"
        default_config = {
            "title": "tkloudi",
            "icon": "assets/icon.png",
            "default_api_paths": ["files/cloudi-api-paths.json"],
            "servers": [],
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    return json.load(f)
            else:
                with open(config_path, "w") as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            return default_config

    def save_config(self):
        config_path = "files/api.conf"
        try:
            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            return False

    def create_widgets(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        api_frame = ttk.LabelFrame(self, text="API")
        api_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        api_frame.columnconfigure(1, weight=1)
        api_frame.rowconfigure(1, weight=1)

        ttk.Label(api_frame, text="API Files:").grid(
            row=0, column=0, sticky="nw", padx=5, pady=5
        )

        paths_frame = tk.Frame(api_frame)
        paths_frame.grid(row=0, column=1, rowspan=1, sticky="nsew", padx=5, pady=5)
        paths_frame.columnconfigure(0, weight=1)
        paths_frame.rowconfigure(0, weight=1)

        paths_v_scroll = ttk.Scrollbar(paths_frame)
        paths_v_scroll.grid(row=0, column=1, sticky="ns")

        self.api_paths_text = tk.Text(
            paths_frame,
            height=3,
            width=40,
            wrap="none",
            yscrollcommand=paths_v_scroll.set,
        )
        self.api_paths_text.grid(row=0, column=0, sticky="ew")
        paths_v_scroll.config(command=self.api_paths_text.yview)

        default_paths = self.config.get(
            "default_api_paths", ["files/cloudi-api-paths.json"]
        )
        for path in default_paths:
            self.api_paths_text.insert(tk.END, path + "\n")

        api_buttons_frame = tk.Frame(api_frame)
        api_buttons_frame.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        browse_button = ttk.Button(
            api_buttons_frame, text="Browse", command=self.browse_api_file
        )
        browse_button.pack(side=tk.LEFT, padx=2)

        load_button = ttk.Button(
            api_buttons_frame, text="Load", command=self.load_api_files
        )
        load_button.pack(side=tk.LEFT, padx=2)

        set_default_button = ttk.Button(
            api_buttons_frame, text="Set Default", command=self.set_default_api_paths
        )
        set_default_button.pack(side=tk.LEFT, padx=2)

        ttk.Label(api_frame, text="Filter:").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )

        filter_frame = tk.Frame(api_frame)
        filter_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        filter_frame.columnconfigure(0, weight=1)

        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self.filter_paths)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=40)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.only_examples_var = tk.BooleanVar(value=False)
        self.only_examples_var.trace("w", self.filter_paths)
        ttk.Checkbutton(
            filter_frame,
            text="Only With Examples",
            variable=self.only_examples_var,
        ).pack(side=tk.LEFT, padx=(10, 0))

        self.show_cloudi_var = tk.BooleanVar(value=False)
        self.show_cloudi_var.trace("w", self.filter_paths)
        ttk.Checkbutton(
            filter_frame,
            text="Show CloudI services",
            variable=self.show_cloudi_var,
        ).pack(side=tk.LEFT, padx=(10, 0))

        ttk.Label(api_frame, text="Services:").grid(
            row=3, column=0, sticky="nw", padx=5, pady=5
        )

        services_frame = tk.Frame(api_frame)
        services_frame.grid(
            row=3, column=1, columnspan=2, sticky="nsew", padx=5, pady=5
        )
        services_frame.columnconfigure(0, weight=1)
        services_frame.rowconfigure(0, weight=1)

        services_v_scroll = ttk.Scrollbar(services_frame)
        services_v_scroll.grid(row=0, column=1, sticky="ns")

        self.services_text = tk.Text(
            services_frame, height=6, wrap="none", yscrollcommand=services_v_scroll.set
        )
        self.services_text.grid(row=0, column=0, sticky="nsew")
        services_v_scroll.config(command=self.services_text.yview)

        self.services_text.bind("<ButtonRelease-1>", self.service_selected)

        request_frame = ttk.LabelFrame(self, text="Request")
        request_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        request_frame.columnconfigure(1, weight=1)

        ttk.Label(request_frame, text="Server:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )

        self.server_var = tk.StringVar(value="http://192.168.0.1:6464")
        self.server_var.trace("w", self.update_endpoint_on_server_change)

        self.server_combo = ttk.Combobox(
            request_frame, textvariable=self.server_var, width=40
        )
        self.server_combo.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        self.load_saved_servers()

        ttk.Label(request_frame, text="Method:").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        self.method_var = tk.StringVar(value="GET")
        method_cb = ttk.Combobox(
            request_frame,
            textvariable=self.method_var,
            values=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            state="readonly",
            width=10,
        )
        method_cb.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(request_frame, text="Endpoint:").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )

        endpoint_frame = tk.Frame(request_frame)
        endpoint_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        endpoint_frame.columnconfigure(0, weight=1)

        self.endpoint_path = ""
        self.endpoint_var = tk.StringVar()
        endpoint_entry = ttk.Entry(
            endpoint_frame, textvariable=self.endpoint_var, width=80
        )
        endpoint_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.send_button = ttk.Button(
            endpoint_frame, text="Send", command=self.send_request
        )
        self.send_button.pack(side=tk.LEFT, padx=(5, 0))

        headers_body_frame = tk.Frame(request_frame)
        headers_body_frame.grid(
            row=4, column=0, columnspan=2, sticky="nsew", padx=5, pady=5
        )
        headers_body_frame.columnconfigure(0, weight=1)
        headers_body_frame.columnconfigure(1, weight=1)
        headers_body_frame.rowconfigure(1, weight=1)

        ttk.Label(headers_body_frame, text="Headers:").grid(
            row=0, column=0, sticky="nw", padx=5, pady=5
        )
        self.headers_frame = tk.Frame(headers_body_frame)
        self.headers_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.headers_frame.columnconfigure(0, weight=1)
        self.headers_frame.rowconfigure(0, weight=1)

        headers_h_scroll = tk.Scrollbar(self.headers_frame, orient="horizontal")
        headers_h_scroll.grid(row=1, column=0, sticky="ew")

        headers_v_scroll = tk.Scrollbar(self.headers_frame)
        headers_v_scroll.grid(row=0, column=1, sticky="ns")

        self.headers_text = tk.Text(
            self.headers_frame,
            wrap="none",
            height=5,
            xscrollcommand=headers_h_scroll.set,
            yscrollcommand=headers_v_scroll.set,
        )
        self.headers_text.grid(row=0, column=0, sticky="nsew")
        headers_h_scroll.config(command=self.headers_text.xview)
        headers_v_scroll.config(command=self.headers_text.yview)

        self.headers_text.insert(
            "1.0",
            '{\n    "Content-Type": "application/json",\n    "Accept": "application/json"\n}',
        )

        body_header_frame = tk.Frame(headers_body_frame)
        body_header_frame.grid(row=0, column=1, sticky="nw", padx=5, pady=5)

        ttk.Label(body_header_frame, text="Body:").pack(side=tk.LEFT)

        self.payload_type = tk.StringVar(value="text")
        ttk.Radiobutton(
            body_header_frame,
            text="Text",
            variable=self.payload_type,
            value="text",
            command=self.toggle_payload_mode,
        ).pack(side=tk.LEFT, padx=(10, 5))

        ttk.Radiobutton(
            body_header_frame,
            text="File",
            variable=self.payload_type,
            value="file",
            command=self.toggle_payload_mode,
        ).pack(side=tk.LEFT, padx=5)

        self.show_example_button = ttk.Button(
            body_header_frame,
            text="Show Example",
            command=self.show_example,
            state="disabled",
        )
        self.show_example_button.pack(side=tk.LEFT, padx=(10, 0))

        self.current_example = None

        self.body_container = tk.Frame(headers_body_frame)
        self.body_container.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        self.body_container.columnconfigure(0, weight=1)
        self.body_container.rowconfigure(0, weight=1)

        self.body_frame = tk.Frame(self.body_container)
        self.body_frame.grid(row=0, column=0, sticky="nsew")
        self.body_frame.columnconfigure(0, weight=1)
        self.body_frame.rowconfigure(0, weight=1)

        body_h_scroll = tk.Scrollbar(self.body_frame, orient="horizontal")
        body_h_scroll.grid(row=1, column=0, sticky="ew")

        body_v_scroll = tk.Scrollbar(self.body_frame)
        body_v_scroll.grid(row=0, column=1, sticky="ns")

        self.body_text = tk.Text(
            self.body_frame,
            wrap="none",
            height=7,
            xscrollcommand=body_h_scroll.set,
            yscrollcommand=body_v_scroll.set,
        )
        self.body_text.grid(row=0, column=0, sticky="nsew")
        body_h_scroll.config(command=self.body_text.xview)
        body_v_scroll.config(command=self.body_text.yview)

        self.file_frame = tk.Frame(self.body_container)
        self.file_path = tk.StringVar()

        file_selection_frame = tk.Frame(self.file_frame)
        file_selection_frame.pack(fill=tk.X, expand=True)

        self.file_label = ttk.Entry(
            file_selection_frame,
            textvariable=self.file_path,
            state="readonly",
            width=40,
        )
        self.file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_file_button = ttk.Button(
            file_selection_frame, text="Browse", command=self.browse_payload_file
        )
        browse_file_button.pack(side=tk.LEFT, padx=(5, 0))

        response_frame = ttk.LabelFrame(self, text="Response")
        response_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        response_frame.columnconfigure(0, weight=1)
        response_frame.rowconfigure(0, weight=1)

        self.response_text_frame = tk.Frame(response_frame)
        self.response_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.response_text_frame.columnconfigure(0, weight=1)
        self.response_text_frame.rowconfigure(0, weight=1)

        response_h_scroll = tk.Scrollbar(self.response_text_frame, orient="horizontal")
        response_h_scroll.grid(row=1, column=0, sticky="ew")

        response_v_scroll = tk.Scrollbar(self.response_text_frame)
        response_v_scroll.grid(row=0, column=1, sticky="ns")

        self.response_text = tk.Text(
            self.response_text_frame,
            wrap="none",
            xscrollcommand=response_h_scroll.set,
            yscrollcommand=response_v_scroll.set,
        )
        self.response_text.grid(row=0, column=0, sticky="nsew")
        response_h_scroll.config(command=self.response_text.xview)
        response_v_scroll.config(command=self.response_text.yview)

        self.load_api_files()

    def toggle_payload_mode(self):
        if self.payload_type.get() == "text":
            self.file_frame.grid_forget()
            self.body_frame.grid(row=0, column=0, sticky="nsew")
        else:
            self.body_frame.grid_forget()
            self.file_frame.grid(row=0, column=0, sticky="nsew")

    def browse_payload_file(self):
        filename = filedialog.askopenfilename(
            title="Select Payload File",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("XML files", "*.xml"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.file_path.set(filename)

    def browse_api_file(self):
        filenames = filedialog.askopenfilenames(
            title="Select API Files",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filenames:
            for filename in filenames:
                current_content = self.api_paths_text.get("1.0", tk.END)
                if filename + "\n" not in current_content:
                    self.api_paths_text.insert(tk.END, filename + "\n")

    def set_default_api_paths(self):
        all_text = self.api_paths_text.get("1.0", tk.END)
        paths = [line.strip() for line in all_text.split("\n") if line.strip()]

        if paths:
            self.config["default_api_paths"] = paths
            if self.save_config():
                messagebox.showinfo("Success", "Default API paths saved successfully")
            else:
                messagebox.showerror("Error", "Failed to save default API paths")
        else:
            messagebox.showerror("Error", "No API paths to save")

    def load_api_files(self):
        self.api_data = []

        all_text = self.api_paths_text.get("1.0", tk.END)
        file_paths = [line.strip() for line in all_text.split("\n") if line.strip()]

        files_loaded = 0

        for filepath in file_paths:
            try:
                if os.path.exists(filepath):
                    with open(filepath, "r") as file:
                        file_data = json.load(file)
                        if isinstance(file_data, list):
                            self.api_data.extend(file_data)
                            files_loaded += 1
                        else:
                            pass
                else:
                    pass
            except Exception as e:
                pass

        example_count = 0
        for service_entry in self.api_data:
            if "service" in service_entry and "paths" in service_entry["service"]:
                for path_entry in service_entry["service"]["paths"]:
                    if "examples" in path_entry:
                        example_count += 1
                    elif "exemplo" in path_entry:
                        example_count += 1

        self.filter_paths()

    def filter_paths(self, *args):
        self.services_text.delete("1.0", tk.END)

        if not self.api_data:
            return

        filter_text = self.filter_var.get().lower()
        show_cloudi = self.show_cloudi_var.get()
        only_examples = self.only_examples_var.get()

        for service_entry in self.api_data:
            if "service" in service_entry:
                service = service_entry["service"]
                service_name = service.get("name", "")

                if "paths" in service:
                    matched_paths = []

                    for path_entry in service["paths"]:
                        if "path" in path_entry and path_entry.get("enabled", False):
                            path = path_entry["path"]
                            if path.endswith("*"):
                                continue

                            if not show_cloudi and path.startswith("/cloudi"):
                                continue

                            if only_examples:
                                has_examples = (
                                    "examples" in path_entry or "exemplo" in path_entry
                                )
                                if not has_examples:
                                    continue

                            if filter_text in path.lower():
                                matched_paths.append(path)

                    if matched_paths:
                        self.services_text.insert(tk.END, f"{service_name}\n")
                        for path in matched_paths:
                            self.services_text.insert(tk.END, f"  {path}\n")

    def service_selected(self, event):
        index = self.services_text.index(f"@{event.x},{event.y}")
        line = self.services_text.get(f"{index} linestart", f"{index} lineend")

        if line.startswith("  "):
            path = line.strip()

            method = "GET"
            path_parts = path.split("/")
            endpoint_parts = path_parts.copy()

            if path_parts and path_parts[-1] == "connect":
                method = "PATCH"
            elif path_parts:
                last_part = path_parts[-1].lower()
                valid_methods = [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                ]

                for valid_method in valid_methods:
                    if last_part == valid_method:
                        method = valid_method.upper()
                        endpoint_parts = path_parts[:-1]
                        break

            self.method_var.set(method)
            endpoint_path = "/".join(endpoint_parts)
            if not endpoint_path:
                endpoint_path = "/"

            self.endpoint_path = endpoint_path

            server = self.server_var.get().rstrip("/")
            full_url = f"{server}{endpoint_path}"

            self.endpoint_var.set(full_url)

            self.current_examples = []

            for service_entry in self.api_data:
                if "service" in service_entry and "paths" in service_entry["service"]:
                    for path_entry in service_entry["service"]["paths"]:
                        if "path" in path_entry and path_entry["path"] == path:
                            if "examples" in path_entry:
                                self.current_examples = path_entry["examples"]
                                break
                            elif "exemplo" in path_entry:
                                example = {
                                    "description": "Example",
                                    "data": path_entry["exemplo"],
                                }
                                self.current_examples = [example]
                                break

            if self.current_examples:
                self.show_example_button.config(state="normal")
            else:
                self.show_example_button.config(state="disabled")

    def show_example(self):
        if not self.current_examples:
            return

        example_window = tk.Toplevel(self)
        example_window.title("API Examples")
        example_window.geometry("700x500")
        example_window.minsize(500, 400)

        example_window.transient(self)
        example_window.grab_set()

        container_frame = tk.Frame(example_window)
        container_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        container_frame.columnconfigure(0, weight=1)
        container_frame.rowconfigure(0, weight=1)

        canvas = tk.Canvas(container_frame)
        scrollbar = ttk.Scrollbar(
            container_frame, orient="vertical", command=canvas.yview
        )
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for i, example in enumerate(self.current_examples):
            example_frame = ttk.LabelFrame(
                scrollable_frame, text=example.get("description", f"Example {i+1}")
            )
            example_frame.pack(fill="both", expand=True, padx=5, pady=5)

            text_frame = tk.Frame(example_frame)
            text_frame.pack(fill="both", expand=True, padx=5, pady=5)
            text_frame.columnconfigure(0, weight=1)
            text_frame.rowconfigure(0, weight=1)

            h_scroll = tk.Scrollbar(text_frame, orient="horizontal")
            h_scroll.grid(row=1, column=0, sticky="ew")

            v_scroll = tk.Scrollbar(text_frame)
            v_scroll.grid(row=0, column=1, sticky="ns")

            example_text = tk.Text(
                text_frame,
                wrap="none",
                height=10,
                xscrollcommand=h_scroll.set,
                yscrollcommand=v_scroll.set,
            )
            example_text.grid(row=0, column=0, sticky="nsew")

            h_scroll.config(command=example_text.xview)
            v_scroll.config(command=example_text.yview)

            try:
                data = example.get("data", {})
                if isinstance(data, (dict, list)):
                    formatted_example = json.dumps(data, indent=2)
                else:
                    formatted_example = str(data)

                example_text.insert("1.0", formatted_example)
                example_text.config(state="disabled")
            except Exception as e:
                example_text.insert("1.0", f"Error formatting example: {str(e)}")

            copy_button = ttk.Button(
                example_frame,
                text="Copy to Request Body",
                command=lambda data=data: self.copy_to_request_body(data),
            )
            copy_button.pack(pady=(0, 5))

        close_button = ttk.Button(
            example_window, text="Close", command=example_window.destroy
        )
        close_button.pack(pady=(5, 10))

        example_window.focus_set()

    def copy_to_request_body(self, data):
        if self.payload_type.get() != "text":
            self.payload_type.set("text")
            self.toggle_payload_mode()

        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2)
            else:
                formatted_data = str(data)

            self.body_text.delete("1.0", tk.END)
            self.body_text.insert("1.0", formatted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy example: {str(e)}")

    def send_request(self):
        method = self.method_var.get()
        full_url = self.endpoint_var.get()

        headers_text = self.headers_text.get("1.0", tk.END).strip()
        try:
            headers = json.loads(headers_text) if headers_text else {}
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON in Headers field")
            return

        if self.payload_type.get() == "text":
            body = self.body_text.get("1.0", tk.END).strip()
        else:
            file_path = self.file_path.get()
            if not file_path:
                messagebox.showerror("Error", "No payload file selected")
                return

            try:
                with open(file_path, "r") as f:
                    body = f.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read payload file: {str(e)}")
                return

        self.response_text.delete("1.0", tk.END)
        self.response_text.insert(
            tk.END, f"Sending {method} request to {full_url}...\n"
        )
        self.update()

        try:
            if method == "GET":
                response = requests.get(
                    full_url, headers=headers, verify=False, timeout=30
                )
            elif method == "POST":
                response = requests.post(
                    full_url, headers=headers, data=body, verify=False, timeout=30
                )
            elif method == "PUT":
                response = requests.put(
                    full_url, headers=headers, data=body, verify=False, timeout=30
                )
            elif method == "PATCH":
                response = requests.patch(
                    full_url, headers=headers, data=body, verify=False, timeout=30
                )
            elif method == "DELETE":
                response = requests.delete(
                    full_url, headers=headers, verify=False, timeout=30
                )
            elif method == "OPTIONS":
                response = requests.options(
                    full_url, headers=headers, verify=False, timeout=30
                )
            elif method == "HEAD":
                response = requests.head(
                    full_url, headers=headers, verify=False, timeout=30
                )
            else:
                self.response_text.delete("1.0", tk.END)
                self.response_text.insert(tk.END, f"Unsupported method: {method}")
                return

            self.response_text.delete("1.0", tk.END)

            self.response_text.insert(tk.END, f"Status: {response.status_code}\n\n")

            self.response_text.insert(tk.END, "Headers:\n")
            for header, value in response.headers.items():
                self.response_text.insert(tk.END, f"{header}: {value}\n")

            self.response_text.insert(tk.END, "\nBody:\n")

            try:
                if response.headers.get("Content-Type", "").startswith(
                    "application/json"
                ):
                    json_response = json.dumps(response.json(), indent=2)
                    self.response_text.insert(tk.END, json_response)
                else:
                    self.response_text.insert(tk.END, response.text)
            except Exception:
                self.response_text.insert(tk.END, response.text)

        except requests.exceptions.Timeout:
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert(
                tk.END, "Error: Request timed out after 30 seconds"
            )
        except requests.exceptions.ConnectionError:
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert(tk.END, "Error: Connection failed")
        except Exception as e:
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert(tk.END, f"Error: {str(e)}")

    def load_saved_servers(self):
        servers = self.config.get("servers", [])
        if servers:
            self.server_combo["values"] = servers
            if servers and not self.server_var.get():
                self.server_var.set(servers[0])

    def update_endpoint_on_server_change(self, *args):
        current_url = self.endpoint_var.get()
        new_server = self.server_var.get().rstrip("/")

        if self.endpoint_path:
            self.endpoint_var.set(f"{new_server}{self.endpoint_path}")
        elif current_url:
            try:
                import urllib.parse

                parsed_url = urllib.parse.urlparse(current_url)
                path = parsed_url.path

                self.endpoint_path = path

                self.endpoint_var.set(f"{new_server}{path}")
            except:
                pass
