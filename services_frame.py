import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import os
import re
import requests
from datetime import datetime
from services_helper import (
    find_closing_bracket,
    extract_service_entries,
    parse_service_entry,
    extract_services_direct,
    parse_services,
    parse_erlang_response,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "files/api.conf")


class ServicesFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.services_data = []
        self.service_uuid_map = {}

        if hasattr(master, "config_data"):
            self.config = master.config_data
        else:
            self.config = self.load_config()

        self.create_widgets()

    def load_config(self):
        config_path = CONFIG_FILE
        default_config = {
            "title": "tkloudi",
            "icon": "assets/icon.png",
            "cloudi_conf_files": [
                os.path.join(SCRIPT_DIR, "files/cloudi_minimal.conf")
            ],
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
        config_path = CONFIG_FILE
        try:
            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            return False

    def create_widgets(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        servers_frame = ttk.LabelFrame(self, text="Servers")
        servers_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        servers_frame.columnconfigure(1, weight=1)

        ttk.Label(servers_frame, text="Server:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )

        server_frame = tk.Frame(servers_frame)
        server_frame.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        server_frame.columnconfigure(0, weight=1)

        self.server_var = tk.StringVar(value="http://192.168.0.1:6464")
        self.server_combo = ttk.Combobox(
            server_frame, textvariable=self.server_var, width=40
        )
        self.server_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        save_server_button = ttk.Button(
            server_frame, text="Save", command=self.save_server
        )
        save_server_button.pack(side=tk.LEFT, padx=(5, 2))

        delete_server_button = ttk.Button(
            server_frame, text="Delete", command=self.delete_server
        )
        delete_server_button.pack(side=tk.LEFT, padx=2)

        self.load_saved_servers()

        ttk.Label(servers_frame, text="Config Files:").grid(
            row=1, column=0, sticky="nw", padx=5, pady=5
        )

        config_list_frame = tk.Frame(servers_frame)
        config_list_frame.grid(
            row=1, column=1, rowspan=1, sticky="nsew", padx=5, pady=5
        )
        config_list_frame.columnconfigure(0, weight=1)
        config_list_frame.rowconfigure(0, weight=1)

        config_v_scroll = ttk.Scrollbar(config_list_frame)
        config_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.config_files_listbox = tk.Listbox(
            config_list_frame,
            height=3,
            exportselection=False,
            yscrollcommand=config_v_scroll.set,
        )
        self.config_files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        config_v_scroll.config(command=self.config_files_listbox.yview)

        default_paths = self.config.get("cloudi_conf_files", [])
        for path in default_paths:
            self.config_files_listbox.insert(tk.END, path)

        self.config_files_listbox.bind(
            "<Double-1>", lambda e: self.load_selected_file()
        )

        config_buttons_frame = tk.Frame(servers_frame)
        config_buttons_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        browse_button = ttk.Button(
            config_buttons_frame, text="Browse", command=self.browse_conf_file
        )
        browse_button.pack(side=tk.LEFT, padx=2)

        load_button = ttk.Button(
            config_buttons_frame, text="Load", command=self.load_selected_file
        )
        load_button.pack(side=tk.LEFT, padx=2)

        unload_button = ttk.Button(
            config_buttons_frame, text="Unload", command=self.unload_services
        )
        unload_button.pack(side=tk.LEFT, padx=2)

        set_default_button = ttk.Button(
            config_buttons_frame,
            text="Set Default",
            command=self.set_default_conf_paths,
        )
        set_default_button.pack(side=tk.LEFT, padx=2)

        edit_button = ttk.Button(
            config_buttons_frame, text="Edit", command=self.edit_conf_file
        )
        edit_button.pack(side=tk.LEFT, padx=2)

        remove_button = ttk.Button(
            config_buttons_frame, text="Remove", command=self.remove_conf_file
        )
        remove_button.pack(side=tk.LEFT, padx=2)

        services_panel = ttk.LabelFrame(self, text="Services")
        services_panel.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        services_panel.columnconfigure(0, weight=1)
        services_panel.rowconfigure(2, weight=1)

        status_frame = tk.Frame(services_panel)
        status_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        ttk.Label(status_frame, text="Auto Status:").pack(side=tk.LEFT, padx=(0, 5))

        self.refresh_var = tk.StringVar(value="disabled")

        ttk.Radiobutton(
            status_frame,
            text="Disabled",
            value="disabled",
            variable=self.refresh_var,
            command=self.toggle_auto_refresh,
        ).pack(side=tk.LEFT, padx=5)

        for interval, label in [
            ("15", "15s"),
            ("30", "30s"),
            ("60", "1m"),
            ("300", "5m"),
            ("900", "15m"),
        ]:
            ttk.Radiobutton(
                status_frame,
                text=label,
                value=interval,
                variable=self.refresh_var,
                command=self.toggle_auto_refresh,
            ).pack(side=tk.LEFT, padx=5)

        self.update_status_btn = ttk.Button(
            status_frame, text="Get Status", command=self.update_service_status
        )
        self.update_status_btn.pack(side=tk.LEFT, padx=(20, 0))

        self.get_config_btn = ttk.Button(
            status_frame, text="Get Config", command=self.get_service_config
        )
        self.get_config_btn.pack(side=tk.LEFT, padx=(5, 0))

        self.status_timer = None

        filter_frame = tk.Frame(services_panel)
        filter_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        filter_frame.columnconfigure(1, weight=1)
        filter_frame.columnconfigure(3, weight=1)

        ttk.Label(filter_frame, text="Name:").grid(
            row=0, column=0, sticky="w", padx=(0, 5)
        )
        self.name_filter_var = tk.StringVar()
        self.name_filter_var.trace("w", self.apply_filters)
        name_filter_entry = ttk.Entry(filter_frame, textvariable=self.name_filter_var)
        name_filter_entry.grid(row=0, column=1, sticky="ew", padx=5)

        ttk.Label(filter_frame, text="Prefix:").grid(
            row=0, column=2, sticky="w", padx=(10, 5)
        )
        self.prefix_filter_var = tk.StringVar()
        self.prefix_filter_var.trace("w", self.apply_filters)
        prefix_filter_entry = ttk.Entry(
            filter_frame, textvariable=self.prefix_filter_var
        )
        prefix_filter_entry.grid(row=0, column=3, sticky="ew", padx=5)

        self.show_cloudi_var = tk.BooleanVar(value=True)
        self.show_cloudi_var.trace("w", self.apply_filters)
        show_cloudi_check = ttk.Checkbutton(
            filter_frame,
            text="Show CloudI services",
            variable=self.show_cloudi_var,
        )
        show_cloudi_check.grid(row=0, column=4, padx=10, sticky="e")

        self.services_container = tk.Frame(services_panel)
        self.services_container.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.services_container.columnconfigure(0, weight=1)
        self.services_container.rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(self.services_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(
            self.services_container, orient="vertical", command=self.canvas.yview
        )

        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_frame.bind(
            "<Configure>", lambda e: self._update_scroll_region()
        )

        self.canvas.bind("<Configure>", lambda e: self._update_canvas_width())

        style = ttk.Style()
        style.configure("Services.TFrame", background="white")
        self.scrollable_frame.configure(style="Services.TFrame")

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        if default_paths:
            self.load_conf_files()

    def _update_scroll_region(self):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _update_canvas_width(self):
        canvas_width = self.services_container.winfo_width() - 20
        self.canvas.itemconfig(1, width=canvas_width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def log_error(self, message):
        if hasattr(self.master, "log_error"):
            self.master.log_error(message)
        # else:
        # print(f"ERROR: {message}")

    def log_info(self, message):
        if hasattr(self.master, "log_info"):
            self.master.log_info(message)
        # else:
        # print(f"INFO: {message}")

    def log_warning(self, message):
        if hasattr(self.master, "log_warning"):
            self.master.log_warning(message)
        # else:
        # print(f"WARNING: {message}")

    def log_debug(self, message):
        if hasattr(self.master, "log_debug"):
            self.master.log_debug(message)
        # else:
        # print(f"DEBUG: {message}")

    def load_saved_servers(self):
        servers = self.config.get("servers", [])
        if servers:
            self.server_combo["values"] = servers
            if servers:
                self.server_var.set(servers[0])
            else:
                self.server_var.set(self.server_var.set(servers[0]))

    def toggle_auto_refresh(self):
        if self.status_timer:
            self.after_cancel(self.status_timer)
            self.status_timer = None

        interval = self.refresh_var.get()
        if interval != "disabled":
            interval_ms = int(interval) * 1000
            self.status_timer = self.after(interval_ms, self.auto_refresh_status)

    def auto_refresh_status(self):
        self.update_service_status(is_auto_refresh=True)

        interval = self.refresh_var.get()
        if interval != "disabled":
            interval_ms = int(interval) * 1000
            self.status_timer = self.after(interval_ms, self.auto_refresh_status)

    def update_service_status(self, is_auto_refresh=False):
        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services_status.json"
        try:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            response = requests.post(
                url, data="[]", headers=headers, verify=False, timeout=10
            )
            if response.status_code == 200:
                if not self.services_data:
                    self.log_warning(
                        "Getting status without configuration loaded. Services will have limited information."
                    )
                    self.display_services(show_warning=True)
                self.process_status_response(response.text, is_auto_refresh)
                for service in self.services_data:
                    self.update_service_display(id(service))
            else:
                self.log_error(
                    f"Error getting service status: HTTP {response.status_code}"
                )
        except Exception as e:
            self.log_error(f"Failed to get service status: {str(e)}")

    def get_service_config(self):
        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services.json"

        try:
            headers = {
                "Accept": "application/json",
            }
            self.log_info(f"Requesting config from: {url}")
            response = requests.get(url, headers=headers, verify=False, timeout=30)

            if response.status_code == 200:
                self.show_config_response(response.text)
            else:
                self.log_error(
                    f"Error getting service config: HTTP {response.status_code} - {response.text[:100]}"
                )
        except Exception as e:
            self.log_error(f"Error getting service config: {str(e)}")
            import traceback

            traceback.print_exc()

    def show_config_response(self, response_text):
        popup = tk.Toplevel(self)
        popup.title("Service Configuration")
        popup.geometry("800x600")
        popup.transient(self.winfo_toplevel())

        frame = ttk.Frame(popup, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        v_scroll = ttk.Scrollbar(text_frame)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        h_scroll = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        text = tk.Text(
            text_frame,
            wrap=tk.NONE,
            xscrollcommand=h_scroll.set,
            yscrollcommand=v_scroll.set,
        )
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        v_scroll.config(command=text.yview)
        h_scroll.config(command=text.xview)

        try:
            parsed = json.loads(response_text)
            formatted = json.dumps(parsed, indent=2)
            text.insert(tk.END, formatted)
        except:
            text.insert(tk.END, response_text)

        ttk.Button(frame, text="Close", command=popup.destroy).pack(pady=(10, 0))

    def process_config_response(self, response_text):
        try:
            parsed_data = json.loads(response_text)

            if isinstance(parsed_data, dict) and "services" in parsed_data:
                config_data = parsed_data["services"]
            elif isinstance(parsed_data, list):
                config_data = parsed_data
            else:
                self.log_error(
                    "Invalid response format - expected JSON with services list"
                )
                return

            if not config_data:
                self.log_warning("No config data found in response")
                return

            unmatched_configs = []
            matched_count = 0

            for config in config_data:
                if not isinstance(config, dict):
                    continue

                uuid = config.get("id", "")

                config_copy = {k: v for k, v in config.items() if k != "id"}

                matched = False
                for service in self.services_data:
                    if service.get("uuid") == uuid:
                        service["metadata"] = service.get("metadata", {})
                        service["metadata"]["config"] = config_copy
                        service["metadata"]["config_original"] = config
                        matched = True
                        matched_count += 1
                        break

                if not matched:
                    unmatched_configs.append(config)

            self.log_info(
                f"Config update: {matched_count} matched, {len(unmatched_configs)} unmatched"
            )

            if unmatched_configs:
                self.show_unmatched_configs(unmatched_configs)

            self.display_services()

        except Exception as e:
            self.log_error(f"Error processing config response: {str(e)}")
            import traceback

            traceback.print_exc()

    def process_status_response(self, response_text, is_auto_refresh=False):
        try:
            parsed_data = json.loads(response_text)

            if isinstance(parsed_data, list):
                status_data = parsed_data
            elif isinstance(parsed_data, dict) and any(
                isinstance(v, list) for v in parsed_data.values()
            ):
                for value in parsed_data.values():
                    if isinstance(value, list):
                        status_data = value
                        break
            else:
                self.log_error(
                    f"Unexpected status response format: {type(parsed_data)}"
                )
                return

            if not status_data:
                return

            if not self.services_data:
                new_services = []
                for status in status_data:
                    service = {}
                    service["uuid"] = status.get("id", "")
                    service["prefix"] = status.get("prefix", "")
                    if "module" in status:
                        service["label"] = status.get("module", "Unknown")
                    elif "file_path" in status:
                        service["label"] = os.path.basename(
                            status.get("file_path", "Unknown")
                        )
                    else:
                        service["label"] = "Unknown Service"
                    service["status"] = status
                    new_services.append(service)
                self.services_data = new_services
                self.display_services(show_warning=True)
                return

            self.update_service_status_indicators(status_data, is_auto_refresh)

        except Exception as e:
            self.log_error(f"Error processing status response: {str(e)}")
            import traceback

            traceback.print_exc()

    def update_service_status_indicators(self, status_data, is_auto_refresh=False):
        if not hasattr(self, "service_widgets"):
            return

        unmatched_services = []
        matched_count = 0

        for service_id, widgets in self.service_widgets.items():
            if "status_indicator" in widgets and "led_id" in widgets:
                widgets["status_indicator"].itemconfig(widgets["led_id"], fill="gray")

            service = next((s for s in self.services_data if id(s) == service_id), None)
            if service and "status" in service:
                service["status"]["suspended"] = False
                service["status"]["conflict"] = False

        conflict_map = {}
        for status in status_data:
            key = None
            status_type = status.get("type", "")
            status_module = status.get("module", "")
            status_file_path = status.get("file_path", "")
            status_prefix = status.get("prefix", "")

            if status_type == "internal" and status_module:
                key = f"internal:{status_module}:{status_prefix}"
            elif status_type == "external" and status_file_path:
                key = f"external:{status_file_path}:{status_prefix}"

            if key:
                if key in conflict_map:
                    conflict_map[key].append(status)
                else:
                    conflict_map[key] = [status]

        for key, statuses in conflict_map.items():
            if len(statuses) > 1:
                for status in statuses:
                    status["conflict"] = True

        for service_id, widgets in self.service_widgets.items():
            service = next((s for s in self.services_data if id(s) == service_id), None)
            if not service:
                continue

            matched_status = None
            for status in status_data:
                if self.is_matching_service(service, status):
                    matched_status = status
                    break

            if matched_status:
                matched_count += 1
                uuid = matched_status.get("id", "")
                if not uuid and "key" in matched_status:
                    uuid = matched_status["key"]
                service["uuid"] = uuid

                key = self.get_service_key(service)
                if key:
                    self.service_uuid_map[key] = uuid

                if "metadata" not in service:
                    service["metadata"] = {}

                service["metadata"]["status"] = matched_status

                service["status"] = {
                    "uuid": matched_status.get("id", ""),
                    "suspended": matched_status.get("suspended", False),
                    "conflict": matched_status.get("conflict", False),
                    "type": matched_status.get("type", ""),
                    "module": matched_status.get("module", ""),
                    "prefix": matched_status.get("prefix", ""),
                    "file_path": matched_status.get("file_path", ""),
                }

                self.update_service_display(service_id)

                if "status_indicator" in widgets and "led_id" in widgets:
                    expected_color = (
                        "yellow"
                        if service["status"].get("suspended", False)
                        else "green"
                    )
                    widgets["status_indicator"].itemconfig(
                        widgets["led_id"], fill=expected_color
                    )

                if "status_tooltip" in widgets:
                    status_text = (
                        "Suspended"
                        if service["status"].get("suspended", False)
                        else "Active"
                    )
                    if service["status"].get("conflict", False):
                        status_text += " (CONFLICT)"
                    widgets["status_tooltip"].configure(text=status_text)
            else:
                if "status_indicator" in widgets and "led_id" in widgets:
                    widgets["status_indicator"].itemconfig(
                        widgets["led_id"], fill="gray"
                    )

                if "status_tooltip" in widgets:
                    widgets["status_tooltip"].configure(text="Not running")

        for status in status_data:
            matched = False
            for service in self.services_data:
                if self.is_matching_service(service, status):
                    matched = True
                    break

            if not matched:
                unmatched_services.append(status)

        # Show unmatched services dialog
        if unmatched_services and not is_auto_refresh:
            self.show_unmatched_services(unmatched_services)

    def update_service_display(self, service_id):
        widgets = self.service_widgets.get(service_id)
        if not widgets:
            return

        service = next((s for s in self.services_data if id(s) == service_id), None)
        if not service:
            return

        suspended = False
        if "status" in service:
            suspended = service["status"].get("suspended", False)

        if "status_indicator" in widgets and "led_id" in widgets:
            if "status" not in service:
                color = "gray"  # No status means gray
            else:
                color = "yellow" if suspended else "green"
            widgets["status_indicator"].itemconfig(widgets["led_id"], fill=color)

            if "status_tooltip" in widgets:
                if "status" not in service:
                    status_text = "Not running"
                else:
                    status_text = "Suspended" if suspended else "Active"
                    if service["status"].get("conflict", False):
                        status_text += " (CONFLICT)"
                widgets["status_tooltip"].configure(text=status_text)

        if "uuid" in service and service["uuid"]:
            uuid = service["uuid"]
            has_conflict = service.get("status", {}).get("conflict", False)
            uuid_container = widgets.get("uuid_container")

            if uuid_container:
                for widget in uuid_container.winfo_children():
                    widget.destroy()

                ttk.Label(
                    uuid_container,
                    text="UUID: ",
                    font=("TkDefaultFont", 8),
                    foreground="red" if has_conflict else "black",
                ).pack(side=tk.LEFT)

                uuid_var = tk.StringVar(value=uuid)
                uuid_entry = ttk.Entry(
                    uuid_container,
                    textvariable=uuid_var,
                    font=("TkDefaultFont", 8),
                    width=36,
                    state="readonly",
                )
                uuid_entry.pack(side=tk.LEFT)
                widgets["uuid_var"] = uuid_var
                widgets["uuid_entry"] = uuid_entry

                if has_conflict:
                    ttk.Label(
                        uuid_container,
                        text=" (CONFLICT)",
                        font=("TkDefaultFont", 8),
                        foreground="red",
                    ).pack(side=tk.LEFT)

    def show_unmatched_services(self, unmatched_services):
        if not unmatched_services:
            return

        popup = tk.Toplevel(self)
        popup.title("Unmatched Services")
        popup.geometry("600x400")
        popup.transient(self.winfo_toplevel())

        frame = ttk.Frame(popup, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=f"Found {len(unmatched_services)} services that don't match any loaded configuration:",
            wraplength=580,
        ).pack(anchor="w", pady=(0, 10))

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        v_scroll = ttk.Scrollbar(text_frame)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        h_scroll = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        text = tk.Text(
            text_frame,
            wrap=tk.NONE,
            width=70,
            height=15,
            xscrollcommand=h_scroll.set,
            yscrollcommand=v_scroll.set,
        )
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        v_scroll.config(command=text.yview)
        h_scroll.config(command=text.xview)

        for i, service in enumerate(unmatched_services):
            uuid = service.get("id", "Unknown UUID")
            prefix = service.get("prefix", "No prefix")
            service_type = service.get("type", "Unknown type")

            conflict_text = " (CONFLICT)" if service.get("conflict", False) else ""

            if service_type == "internal":
                module = service.get("module", "Unknown module")
                text.insert(
                    tk.END,
                    f"{i+1}. UUID: {uuid}{conflict_text}\n   Type: {service_type}\n   Prefix: {prefix}\n   Module: {module}\n\n",
                )
            else:
                file_path = service.get("file_path", "Unknown file")
                text.insert(
                    tk.END,
                    f"{i+1}. UUID: {uuid}{conflict_text}\n   Type: {service_type}\n   Prefix: {prefix}\n   File: {file_path}\n\n",
                )

        text.config(state=tk.DISABLED)

        ttk.Button(frame, text="Close", command=popup.destroy).pack(pady=(10, 0))

    def browse_conf_file(self):
        filenames = filedialog.askopenfilenames(
            title="Select CloudI Config Files",
            filetypes=[("Config files", "*.conf"), ("All files", "*.*")],
        )
        if filenames:
            for filename in filenames:
                existing_files = self.config_files_listbox.get(0, tk.END)
                if filename not in existing_files:
                    self.config_files_listbox.insert(tk.END, filename)

    def set_default_conf_paths(self):
        paths = list(self.config_files_listbox.get(0, tk.END))

        if paths:
            self.config["cloudi_conf_files"] = paths
            if self.save_config():
                messagebox.showinfo(
                    "Success", "Default CloudI config paths saved successfully"
                )
            else:
                messagebox.showerror(
                    "Error", "Failed to save default CloudI config paths"
                )
        else:
            messagebox.showerror("Error", "No CloudI config paths to save")

    def edit_conf_file(self):
        selected_idx = self.config_files_listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Warning", "Please select a config file to edit")
            return

        file_path = self.config_files_listbox.get(selected_idx)

        try:
            with open(file_path, "r") as f:
                file_content = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")
            return

        editor_window = tk.Toplevel(self)
        editor_window.title(f"Edit {os.path.basename(file_path)}")
        editor_window.geometry("800x600")

        editor_window.transient(self)
        editor_window.grab_set()

        editor_frame = tk.Frame(editor_window)
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        h_scroll = tk.Scrollbar(editor_frame, orient="horizontal")
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        v_scroll = tk.Scrollbar(editor_frame)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        text_editor = tk.Text(
            editor_frame,
            wrap="none",
            xscrollcommand=h_scroll.set,
            yscrollcommand=v_scroll.set,
        )
        text_editor.pack(fill=tk.BOTH, expand=True)

        h_scroll.config(command=text_editor.xview)
        v_scroll.config(command=text_editor.yview)

        text_editor.insert("1.0", file_content)

        button_frame = tk.Frame(editor_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        def save_file():
            try:
                with open(file_path, "w") as f:
                    f.write(text_editor.get("1.0", tk.END))
                messagebox.showinfo("Success", "File saved successfully")
                self.load_conf_files()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

        save_button = ttk.Button(button_frame, text="Save", command=save_file)
        save_button.pack(side=tk.RIGHT, padx=(5, 0))
        cancel_button = ttk.Button(
            button_frame, text="Cancel", command=editor_window.destroy
        )
        cancel_button.pack(side=tk.RIGHT, padx=5)

    def complete_config_text(self, text):
        if text.startswith("[") and not text.rstrip().endswith("]"):
            end_index = find_closing_bracket(text, 0)
            if end_index != -1:
                return text[: end_index + 1]
            else:
                return text + "]"
        return text

    def load_conf_files(self):
        self.services_data = []

        file_paths = list(self.config_files_listbox.get(0, tk.END))

        files_loaded = 0

        for filepath_input in file_paths:
            filepath_variations = [
                filepath_input,
                os.path.join(os.getcwd(), filepath_input),
                os.path.join(os.path.dirname(__file__), filepath_input),
                os.path.abspath(filepath_input),
            ]

            success = False
            for filepath in filepath_variations:

                if not os.path.exists(filepath):
                    continue

                try:
                    with open(filepath, "r") as file:
                        conf_content = file.read()

                    services = extract_services_direct(conf_content, filepath)

                    if not services:
                        services = parse_services(conf_content, filepath)

                    if services:
                        for s in services:
                            if "original_entry" in s and s["original_entry"]:
                                s.setdefault("metadata", {})["config_service_add"] = (
                                    self.complete_config_text(s["original_entry"])
                                )
                        self.services_data.extend(services)
                        files_loaded += 1
                        success = True
                        break

                except Exception as e:
                    import traceback

                    traceback.print_exc()

            if not success:
                print(f"Failed to load from any path variation of: {filepath_input}")

        self.display_services()

        if files_loaded == 0:
            self.log_error("No CloudI config files could be loaded")

    def apply_filters(self, *args):
        if hasattr(self, "services_data"):
            self.display_services()

    def display_services(self, show_warning=False):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        self.service_widgets = {}

        if not self.services_data:
            if show_warning:
                warning_label = ttk.Label(
                    self.scrollable_frame,
                    text="Warning: No configuration loaded. Limited service information available.",
                    foreground="red",
                    font=("TkDefaultFont", 10, "bold"),
                )
                warning_label.pack(pady=(20, 10))
            else:
                no_services_label = ttk.Label(
                    self.scrollable_frame,
                    text="No services found. Please load a valid CloudI configuration file.",
                )
                no_services_label.pack(pady=20)
                return

        filtered_services = []
        show_cloudi = self.show_cloudi_var.get()
        name_filter = self.name_filter_var.get().lower()
        prefix_filter = self.prefix_filter_var.get().lower()

        for service in self.services_data:
            if not service.get("uuid"):
                key = self.get_service_key(service)
                if key and key in self.service_uuid_map:
                    service["uuid"] = self.service_uuid_map[key]

            if not show_cloudi and service.get("prefix", "").startswith("/cloudi"):
                continue

            if name_filter and name_filter not in service.get("label", "").lower():
                continue

            if prefix_filter and prefix_filter not in service.get("prefix", "").lower():
                continue

            filtered_services.append(service)

        table_frame = ttk.Frame(self.scrollable_frame)
        table_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
        table_frame.columnconfigure(1, weight=1)

        header_row = ttk.Frame(table_frame)
        header_row.pack(fill=tk.X, pady=5)
        header_row.columnconfigure(1, weight=1)
        ttk.Label(
            header_row, text="Status", width=8, font=("TkDefaultFont", 9, "bold")
        ).grid(row=0, column=0, padx=5)
        ttk.Label(header_row, text="Service", font=("TkDefaultFont", 9, "bold")).grid(
            row=0, column=1, padx=5, sticky="w"
        )
        ttk.Label(
            header_row, text="Actions", width=12, font=("TkDefaultFont", 9, "bold")
        ).grid(row=0, column=2, padx=5)
        separator = ttk.Separator(table_frame, orient="horizontal")
        separator.pack(fill=tk.X, pady=5)

        for idx, service in enumerate(filtered_services):
            row_frame = ttk.Frame(table_frame)
            row_frame.pack(fill=tk.X, pady=3)
            row_frame.columnconfigure(1, weight=1)
            service_id = id(service)
            self.service_widgets[service_id] = {}
            self.service_widgets[service_id]["frame"] = row_frame

            status_cell = ttk.Frame(row_frame, width=40)
            status_cell.grid(row=0, column=0, rowspan=2, padx=5)
            status_indicator = tk.Canvas(
                status_cell,
                width=16,
                height=16,
                bg=self.winfo_toplevel()["bg"],
                highlightthickness=0,
            )
            status_indicator.pack(pady=10)
            led_color = "gray"
            if "status" in service:
                led_color = (
                    "yellow" if service["status"].get("suspended", False) else "green"
                )
            led_id = status_indicator.create_oval(
                2, 2, 14, 14, fill=led_color, outline="black"
            )
            self.service_widgets[service_id]["status_indicator"] = status_indicator
            self.service_widgets[service_id]["led_id"] = led_id
            self.service_widgets[service_id]["status_cell"] = status_cell

            status_tooltip_text = "Unknown status"
            if "status" in service:
                status_tooltip_text = (
                    "Suspended"
                    if service["status"].get("suspended", False)
                    else "Active"
                )
                if service["status"].get("conflict", False):
                    status_tooltip_text += " (CONFLICT)"
            status_tooltip = tk.Label(
                status_cell,
                text=status_tooltip_text,
                background="#ffffe0",
                relief="solid",
                borderwidth=1,
            )
            status_tooltip.pack_forget()
            self.service_widgets[service_id]["status_tooltip"] = status_tooltip
            status_indicator.bind(
                "<Enter>",
                lambda e, tip=status_tooltip, w=status_indicator: tip.place(
                    x=w.winfo_rootx(), y=w.winfo_rooty() + 20
                ),
            )
            status_indicator.bind(
                "<Leave>", lambda e, tip=status_tooltip: tip.place_forget()
            )

            service_cell = ttk.Frame(row_frame)
            service_cell.grid(row=0, column=1, sticky="ew", padx=5)
            service_cell.columnconfigure(0, weight=1)
            self.service_widgets[service_id]["service_cell"] = service_cell
            name_frame = ttk.Frame(service_cell)
            name_frame.grid(row=0, column=0, sticky="ew")
            name_frame.columnconfigure(0, weight=1)
            label = ttk.Label(
                name_frame,
                text=f"{idx+1}. {service.get('label', 'Unknown')} ({service.get('prefix', 'unknown')})",
                wraplength=400,
            )
            label.grid(row=0, column=0, sticky="w")
            label.bind("<Button-1>", lambda e, s=service: self.show_service_details(s))
            self.service_widgets[service_id]["label"] = label

            uuid_container = ttk.Frame(service_cell)
            uuid_container.grid(row=1, column=0, sticky="w", pady=(0, 5))
            self.service_widgets[service_id]["uuid_container"] = uuid_container
            if "uuid" in service and service["uuid"]:
                uuid_label = ttk.Label(
                    uuid_container,
                    text=f"UUID: {service['uuid']}",
                    font=("TkDefaultFont", 8),
                    foreground=(
                        "black"
                        if not service.get("status", {}).get("conflict", False)
                        else "red"
                    ),
                )
                uuid_label.pack(side=tk.LEFT, anchor="w")
                uuid_label.bind(
                    "<Button-1>", lambda e, s=service: self.show_service_details(s)
                )
                self.service_widgets[service_id]["uuid_label"] = uuid_label
            else:
                ttk.Label(
                    uuid_container, text="UUID: ", font=("TkDefaultFont", 8)
                ).pack(side=tk.LEFT)
                uuid_var = tk.StringVar(value="")
                uuid_entry = ttk.Entry(
                    uuid_container,
                    textvariable=uuid_var,
                    width=36,
                    font=("TkDefaultFont", 8),
                )
                uuid_entry.pack(side=tk.LEFT)
                self.service_widgets[service_id]["uuid_var"] = uuid_var
                self.service_widgets[service_id]["uuid_entry"] = uuid_entry
                uuid_var.trace_add(
                    "write",
                    lambda n, i, m, s=service, var=uuid_var: self._update_uuid(s, var),
                )

            actions_cell = ttk.Frame(row_frame)
            actions_cell.grid(row=0, column=2, rowspan=2, padx=5)
            self.service_widgets[service_id]["actions_cell"] = actions_cell

            actions_var = tk.StringVar()
            actions_dropdown = ttk.Combobox(
                actions_cell,
                values=[
                    "Actions",
                    "Subscriptions",
                    "Status",
                    "Remove",
                    "Add",
                    "Suspend",
                    "Resume",
                    "Details",
                ],
                state="readonly",
                width=12,
            )
            actions_dropdown.set("Actions")
            actions_dropdown.pack(pady=10)

            self.service_widgets[service_id]["actions_dropdown"] = actions_dropdown
            self.service_widgets[service_id]["actions_var"] = actions_var

            service_actions = {
                "Subscriptions": lambda s=service: self.show_subscriptions(s),
                "Status": lambda s=service: self.show_status(s),
                "Remove": lambda s=service: self.remove_service(s),
                "Add": lambda s=service: self.add_service(s),
                "Suspend": lambda s=service: self.suspend_service(s),
                "Resume": lambda s=service: self.resume_service(s),
                "Details": lambda s=service: self.show_service_details(s),
            }

            def execute_action(
                event, s=service, actions=service_actions, dropdown=actions_dropdown
            ):
                selected = dropdown.get()
                if selected != "Actions" and selected in actions:
                    actions[selected]()
                dropdown.set("Actions")

            actions_dropdown.bind("<<ComboboxSelected>>", execute_action)

        self._update_scroll_region()

    def _update_uuid(self, service, var):
        service["uuid"] = var.get()
        key = self.get_service_key(service)
        if key and var.get():
            self.service_uuid_map[key] = var.get()

    def show_service_details(self, service):
        """Show a popup with service details in tabs"""
        details_window = tk.Toplevel(self)
        details_window.title(f"Service Details: {service.get('label', 'Unknown')}")
        details_window.geometry("800x500")
        details_window.transient(self.winfo_toplevel())

        main_frame = ttk.Frame(details_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_text = f"{service.get('label', 'Unknown Service')}\nPrefix: {service.get('prefix', 'Unknown')}"
        if "uuid" in service and service["uuid"]:
            title_text += f"\nUUID: {service['uuid']}"

        title_label = ttk.Label(
            main_frame, text=title_text, font=("TkDefaultFont", 10, "bold")
        )
        title_label.pack(anchor="w", pady=(0, 10))

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        status_frame = ttk.Frame(notebook, padding=5)
        notebook.add(status_frame, text="Status")

        status_text = self.create_scrolled_text(status_frame)

        self.fill_status_tab(status_text, service)

        close_button = ttk.Button(
            main_frame, text="Close", command=details_window.destroy
        )
        close_button.pack(pady=(10, 0))

    def create_scrolled_text(self, parent):
        """Create a scrolled text widget"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)

        v_scroll = ttk.Scrollbar(frame)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        h_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        text = tk.Text(
            frame,
            wrap=tk.NONE,
            xscrollcommand=h_scroll.set,
            yscrollcommand=v_scroll.set,
        )
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        v_scroll.config(command=text.yview)
        h_scroll.config(command=text.xview)

        return text

    def fill_config_tab(self, text_widget, service):
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)

        original_entry = service.get("original_entry", "")

        if original_entry:
            entry_lines = original_entry.strip().split("\n")
            formatted_entry = ""

            text_widget.insert(tk.END, "[\n")

            for line in entry_lines:
                text_widget.insert(tk.END, "    " + line + "\n")

            text_widget.insert(tk.END, "]")
        elif "metadata" in service and "config" in service["metadata"]:
            try:
                text_widget.insert(tk.END, "[\n")

                text_widget.insert(tk.END, "    [\n")

                config = service["metadata"]["config"]

                if isinstance(config, dict):
                    for key, value in config.items():
                        if key == "id":  # Skip ID field
                            continue

                        if key == "prefix":
                            text_widget.insert(
                                tk.END, f'        {{prefix, "{value}"}},\n'
                            )
                        elif key == "type":
                            text_widget.insert(tk.END, f"        {{type, {value}}},\n")
                        elif key == "module":
                            text_widget.insert(
                                tk.END, f"        {{module, {value}}},\n"
                            )
                        elif key == "args" and isinstance(value, list):
                            text_widget.insert(tk.END, f"        {{args, [\n")
                            for arg in value:
                                if isinstance(arg, dict):
                                    for arg_key, arg_value in arg.items():
                                        if isinstance(arg_value, str):
                                            text_widget.insert(
                                                tk.END,
                                                f'            {{{arg_key}, "{arg_value}"}},\n',
                                            )
                                        else:
                                            text_widget.insert(
                                                tk.END,
                                                f"            {{{arg_key}, {arg_value}}},\n",
                                            )
                            text_widget.insert(tk.END, f"        ]}}\n")
                        else:
                            if isinstance(value, str):
                                text_widget.insert(
                                    tk.END, f'        {{{key}, "{value}"}},\n'
                                )
                            else:
                                text_widget.insert(
                                    tk.END, f"        {{{key}, {value}}},\n"
                                )

                text_widget.insert(tk.END, "    ]\n")

                text_widget.insert(tk.END, "]")
            except Exception as e:
                self.log_error(f"Error formatting config data: {str(e)}")
                text_widget.insert(tk.END, "Error parsing service configuration")
        else:
            text_widget.insert(tk.END, "No configuration available")

        text_widget.tag_configure("heading", font=("TkDefaultFont", 10, "bold"))
        text_widget.config(state=tk.DISABLED)

    def fill_status_tab(self, text_widget, service):
        """Fill the status tab with service status data"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)

        if "status" in service:
            suspended = service["status"].get("suspended", False)
            status_text = "SUSPENDED" if suspended else "ACTIVE"
            if service["status"].get("conflict", False):
                status_text += " (CONFLICT)"

            text_widget.insert(tk.END, f"Current Status: {status_text}\n\n", "heading")

        if "metadata" in service and "status" in service["metadata"]:
            text_widget.insert(tk.END, "Status Details:\n", "heading")
            status = service["metadata"]["status"]

            try:
                formatted_status = json.dumps(status, indent=2)
                text_widget.insert(tk.END, formatted_status)
            except:
                for key, value in status.items():
                    text_widget.insert(tk.END, f"{key}: {value}\n")
        else:
            text_widget.insert(tk.END, "No status data available.")

        text_widget.tag_configure("heading", font=("TkDefaultFont", 10, "bold"))
        text_widget.config(state=tk.DISABLED)

    def generate_tooltip_text(self, service):
        pass

    def create_tooltip(self, widget, text):
        pass

    def show_subscriptions(self, service):
        uuid = service.get("uuid", "")
        if not uuid:
            messagebox.showerror("Error", "Service UUID is required but not available")
            return

        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/service_subscriptions.erl"
        payload = f'"{uuid}"'

        self.perform_service_action(
            url, payload, f"Subscriptions for {service.get('label', 'Unknown')}"
        )

    def show_status(self, service):
        uuid = service.get("uuid", "")
        if not uuid:
            messagebox.showerror("Error", "Service UUID is required but not available")
            return

        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services_status.erl"
        payload = f'["{uuid}"]'

        self.perform_service_action(
            url, payload, f"Status for {service.get('label', 'Unknown')}"
        )

    def suspend_service(self, service):
        uuid = service.get("uuid", "")
        if not uuid:
            messagebox.showerror("Error", "Service UUID is required but not available")
            return

        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services_suspend.erl"
        payload = f'["{uuid}"]'

        self.perform_service_action(
            url, payload, f"Suspend {service.get('label', 'Unknown')}"
        )

    def resume_service(self, service):
        uuid = service.get("uuid", "")
        if not uuid:
            messagebox.showerror("Error", "Service UUID is required but not available")
            return

        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services_resume.erl"
        payload = f'["{uuid}"]'

        self.perform_service_action(
            url, payload, f"Resume {service.get('label', 'Unknown')}"
        )

    def perform_service_action(self, url, payload, title):
        try:
            headers = {
                "Content-Type": "application/erlang",
                "Accept": "application/erlang",
            }

            response = requests.post(
                url, data=payload, headers=headers, verify=False, timeout=10
            )

            result_window = tk.Toplevel(self)
            result_window.title(title)
            result_window.geometry("600x400")
            result_window.transient(self.winfo_toplevel())

            frame = ttk.Frame(result_window, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(
                frame,
                text=f"Status: {response.status_code} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ).pack(anchor="w", pady=(0, 10))

            text_frame = ttk.Frame(frame)
            text_frame.pack(fill=tk.BOTH, expand=True)

            v_scroll = ttk.Scrollbar(text_frame)
            v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

            h_scroll = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL)
            h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

            result_text = tk.Text(
                text_frame,
                wrap=tk.NONE,
                xscrollcommand=h_scroll.set,
                yscrollcommand=v_scroll.set,
            )
            result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            v_scroll.config(command=result_text.yview)
            h_scroll.config(command=result_text.xview)

            # Insert response content
            if response.status_code == 200:
                result_text.insert(tk.END, response.text)

                try:
                    parsed = json.loads(response.text)
                    formatted = json.dumps(parsed, indent=2)
                    result_text.delete("1.0", tk.END)
                    result_text.insert(tk.END, formatted)
                except:
                    pass
            else:
                result_text.insert(
                    tk.END, f"Error: HTTP {response.status_code}\n\n{response.text}"
                )

            ttk.Button(frame, text="Close", command=result_window.destroy).pack(
                pady=(10, 0)
            )

            if "suspend" in url or "resume" in url:
                self.after(1000, self.update_service_status)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform action: {str(e)}")

    def remove_service(self, service):
        uuid = service.get("uuid", "")
        if not uuid:
            messagebox.showerror("Error", "Service UUID is required for removal")
            return
        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services_remove.erl"
        payload = json.dumps([uuid])
        try:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            response = requests.post(
                url, data=payload, headers=headers, verify=False, timeout=10
            )
            if response.status_code == 200:
                messagebox.showinfo("Success", "Service removed successfully")
                service["uuid"] = ""
                self.update_service_display(id(service))
                self.update_service_status()
            else:
                messagebox.showerror(
                    "Error", f"Failed to remove service: HTTP {response.status_code}"
                )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove service: {str(e)}")

    def add_service(self, service):
        popup = tk.Toplevel(self)
        popup.title("Add Service")
        popup.geometry("600x400")
        popup.transient(self.winfo_toplevel())

        frame = ttk.Frame(popup, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        top_frame = tk.Frame(frame)
        top_frame.pack(fill=tk.X)
        ttk.Label(top_frame, text="Enter request body for adding the service:").pack(
            side=tk.LEFT, anchor="w"
        )

        button_frame = tk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT)

        def send_add_request():
            body_text = text_editor.get("1.0", tk.END).strip()
            if not body_text:
                messagebox.showwarning("Warning", "Request body cannot be empty")
                return
            server = self.server_var.get().rstrip("/")
            url = f"{server}/cloudi/api/rpc/services_add.erl"
            try:
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
                response = requests.post(
                    url, data=body_text, headers=headers, verify=False, timeout=10
                )
                if response.status_code == 200:
                    messagebox.showinfo("Success", "Service added successfully")
                    self.update_service_status()
                    popup.destroy()
                else:
                    messagebox.showerror(
                        "Error", f"Failed to add service: HTTP {response.status_code}"
                    )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add service: {str(e)}")

        send_button = ttk.Button(button_frame, text="Send", command=send_add_request)
        send_button.pack(side=tk.RIGHT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=popup.destroy)
        cancel_button.pack(side=tk.RIGHT, padx=5)

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        v_scroll = ttk.Scrollbar(text_frame)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text_editor = tk.Text(text_frame, wrap="none", yscrollcommand=v_scroll.set)
        text_editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.config(command=text_editor.yview)

    def save_server(self):
        server = self.server_var.get().strip()
        if not server:
            messagebox.showwarning("Warning", "Please enter a server URL")
            return

        servers = self.config.get("servers", [])
        if server not in servers:
            servers.append(server)
            self.config["servers"] = servers
            if self.save_config():
                self.server_combo["values"] = servers
                messagebox.showinfo("Success", "Server saved")
            else:
                messagebox.showerror("Error", "Failed to save server")
        else:
            messagebox.showinfo("Info", "Server already exists")

    def delete_server(self):
        server = self.server_var.get().strip()
        if not server:
            messagebox.showwarning("Warning", "Please select a server to delete")
            return

        servers = self.config.get("servers", [])
        if server in servers:
            servers.remove(server)
            self.config["servers"] = servers
            if self.save_config():
                self.server_combo["values"] = servers
                if servers:
                    self.server_var.set(servers[0])
                else:
                    self.server_var.set("http://192.168.0.1:6464")
                messagebox.showinfo("Success", "Server deleted")
            else:
                messagebox.showerror("Error", "Failed to delete server")
        else:
            messagebox.showwarning("Warning", "Server not found in saved servers")

    def remove_conf_file(self):
        selected_idx = self.config_files_listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Warning", "Please select a config file to remove")
            return

        self.config_files_listbox.delete(selected_idx)

    def load_selected_file(self):
        selected_idx = self.config_files_listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Warning", "Please select a config file to load")
            return

        file_path = self.config_files_listbox.get(selected_idx)
        self.services_data = []

        filepath_variations = [
            file_path,
            os.path.join(os.getcwd(), file_path),
            os.path.join(os.path.dirname(__file__), file_path),
            os.path.abspath(file_path),
        ]

        success = False
        for filepath in filepath_variations:
            # print(f"Attempting to load configuration from: {filepath}")

            if not os.path.exists(filepath):
                # print(f"File not found: {filepath}")
                continue

            try:
                with open(filepath, "r") as file:
                    conf_content = file.read()

                # print( f"Successfully read file: {filepath}, size: {len(conf_content)} bytes")

                services = extract_services_direct(conf_content, filepath)

                if not services:
                    # print("Direct extraction failed, trying legacy parser...")
                    services = parse_services(conf_content, filepath)

                if services:
                    self.services_data.extend(services)
                    success = True
                    # print(f"Successfully loaded {len(services)} services from: {filepath}")
                    break
                # else:
                # print(f"No services found in {filepath}")
            except Exception as e:
                import traceback

                # print(f"Error processing file {filepath}: {str(e)}")
                traceback.print_exc()

        if not success:
            # print(f"Failed to load from any path variation of: {file_path}")
            if hasattr(self, "log_error"):
                self.log_error(f"Failed to load config file: {file_path}")
        # else:
        # print(f"Total services found: {len(self.services_data)}")

        self.display_services()

    def is_matching_service(self, service, status):
        sprefix = service.get("prefix", "").strip().lower().rstrip("/")
        stprefix = status.get("prefix", "").strip().lower().rstrip("/")
        if sprefix != stprefix:
            return False

        if "module" in service and "module" in status:
            if (
                service.get("module", "").strip().lower()
                == status.get("module", "").strip().lower()
            ):
                return True
        elif "file_path" in service and "file_path" in status:
            sfile = os.path.basename(service.get("file_path", "")).strip().lower()
            stfile = os.path.basename(status.get("file_path", "")).strip().lower()
            if sfile == stfile:
                return True

        return False

    def get_service_key(self, service):
        """Generate a unique key for a service based on its type and properties."""
        if "module" in service and "prefix" in service:
            return f"internal:{service['module']}:{service['prefix']}"
        elif "file_path" in service and "prefix" in service:
            return f"external:{service['file_path']}:{service['prefix']}"
        return None

    def unload_services(self):
        """Clear all loaded service configurations"""
        self.services_data = []
        self.service_uuid_map = {}
        self.display_services()
        self.log_info("Services unloaded")
