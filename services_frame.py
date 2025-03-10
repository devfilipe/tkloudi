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
        config_path = "files/api.conf"
        default_config = {
            "title": "tkloudi",
            "icon": "assets/icon.png",
            "cloudi_conf_files": ["files/cloudi_minimal.conf"],
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
            # print(f"Error loading config: {e}")
            return default_config

    def save_config(self):
        config_path = "files/api.conf"
        try:
            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            # print(f"Error saving config: {e}")
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
            config_buttons_frame, text="Load Selected", command=self.load_selected_file
        )
        load_button.pack(side=tk.LEFT, padx=2)

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
            status_frame, text="Update Status", command=self.update_service_status
        )
        self.update_status_btn.pack(side=tk.LEFT, padx=(20, 0))

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
        if self.tab_control.index(self.tab_control.select()) == 0:
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
            # print(f"Auto-refresh enabled every {interval} seconds")

    def auto_refresh_status(self):
        self.update_service_status(is_auto_refresh=True)

        interval = self.refresh_var.get()
        if interval != "disabled":
            interval_ms = int(interval) * 1000
            self.status_timer = self.after(interval_ms, self.auto_refresh_status)

    def update_service_status(self, is_auto_refresh=False):
        server = self.server_var.get().rstrip("/")
        url = f"{server}/cloudi/api/rpc/services_status.erl"

        # print(f"Requesting services status from: {url}")
        try:
            headers = {
                "Content-Type": "application/erlang",
                "Accept": "application/erlang",
            }
            response = requests.post(
                url, data="[]", headers=headers, verify=False, timeout=10
            )

            if response.status_code == 200:
                # print(f"Got successful response, length: {len(response.text)} bytes")
                # print(f"Response preview: {response.text[:100]}...")
                self.process_status_response(response.text, is_auto_refresh)
            # else:
            # print(f"Error getting service status: HTTP {response.status_code}")
            # print(f"Response: {response.text}")
        except Exception as e:
            print(f"Error updating service status: {str(e)}")

    def process_status_response(self, response_text, is_auto_refresh=False):
        try:

            status_data = parse_erlang_response(response_text)
            if not status_data:
                # print("No status data found in response")
                return

            # print(f"Received status for {len(status_data)} services")

            self.update_service_status_indicators(status_data, is_auto_refresh)

        except Exception as e:
            # print(f"Error processing status response: {str(e)}")
            import traceback

            traceback.print_exc()

    def update_service_status_indicators(self, status_data, is_auto_refresh=False):
        if not hasattr(self, "service_widgets"):
            # print("No service widgets available for updating status")
            return

        unmatched_services = []
        matched_count = 0

        conflict_map = {}
        for status in status_data:
            key = None
            if status.get("type") == "internal" and "module" in status:
                key = f"internal:{status['module']}:{status['prefix']}"
            elif status.get("type") == "external" and "file_path" in status:
                key = f"external:{status['file_path']}:{status['prefix']}"

            if key:
                if key in conflict_map:
                    conflict_map[key].append(status)
                else:
                    conflict_map[key] = [status]

        for key, statuses in conflict_map.items():
            if len(statuses) > 1:
                for status in statuses:
                    status["conflict"] = True
                # print(f"Found conflict: {key} has {len(statuses)} instances")

        for service_id, widgets in self.service_widgets.items():
            service = next((s for s in self.services_data if id(s) == service_id), None)
            if not service:
                continue

            # print(f"Checking service: {service.get('label')}, prefix: {service.get('prefix')}")

            matched_status = None
            for status in status_data:
                if self.is_matching_service(service, status):
                    matched_status = status
                    # print(f"Found match for {service.get('label')} with uuid: {status.get('uuid')}")
                    # print(f"Status object: {matched_status}")
                    suspended = matched_status.get("suspended", False)
                    # print(f"*** SUSPENDED FLAG VALUE: {suspended} (type: {type(suspended).__name__}) ***")
                    break

            if matched_status:
                matched_count += 1
                uuid = matched_status.get("uuid", "")
                if not uuid and "key" in matched_status:
                    uuid = matched_status["key"]
                service["uuid"] = uuid

                key = self.get_service_key(service)
                if key:
                    self.service_uuid_map[key] = uuid

                service["status"] = {
                    "uuid": matched_status.get("uuid", ""),
                    "suspended": matched_status.get("suspended", False),
                    "conflict": matched_status.get("conflict", False),
                    "type": matched_status.get("type", ""),
                    "module": matched_status.get("module", ""),
                    "prefix": matched_status.get("prefix", ""),
                    "file_path": matched_status.get("file_path", ""),
                }

                # print(f"Service status after update: suspended = {service['status'].get('suspended', False)}")

                self.update_service_display(service_id)

                if "status_indicator" in widgets and "led_id" in widgets:
                    current_color = widgets["status_indicator"].itemcget(
                        widgets["led_id"], "fill"
                    )
                    expected_color = (
                        "yellow"
                        if service["status"].get("suspended", False)
                        else "green"
                    )
                    # print( f"LED color check: Current={current_color}, Expected={expected_color}")

                    if current_color != expected_color:
                        # print(f"*** FORCING COLOR UPDATE to {expected_color} ***")
                        widgets["status_indicator"].itemconfig(
                            widgets["led_id"], fill=expected_color
                        )

                # print( f"Updated status for {service.get('label', 'Unknown')}: {'Suspended' if matched_status.get('suspended', False) else 'Active'}")
            else:
                if "status_indicator" in widgets:
                    widgets["status_indicator"].itemconfig(
                        widgets["led_id"], fill="gray"
                    )

                if "uuid_label" in widgets:
                    widgets["uuid_label"].grid_forget()

                if "uuid_entry" not in widgets:
                    uuid_frame = tk.Frame(widgets["frame"])
                    uuid_frame.grid(row=1, column=0, sticky="w", padx=25)

                    ttk.Label(uuid_frame, text="UUID: ").pack(side=tk.LEFT)

                    uuid_var = tk.StringVar(value=service.get("uuid", ""))
                    uuid_entry = ttk.Entry(uuid_frame, textvariable=uuid_var, width=36)
                    uuid_entry.pack(side=tk.LEFT)

                    widgets["uuid_frame"] = uuid_frame
                    widgets["uuid_entry"] = uuid_entry
                    widgets["uuid_var"] = uuid_var

                    def update_uuid(name, index, mode, s=service, var=uuid_var):
                        s["uuid"] = var.get()

                        key = self.get_service_key(s)
                        if key and var.get():
                            self.service_uuid_map[key] = var.get()

                    uuid_var.trace_add("write", update_uuid)

        for status in status_data:
            matched = False
            for service in self.services_data:
                if self.is_matching_service(service, status):
                    matched = True
                    break

            if not matched:
                unmatched_services.append(status)

        if unmatched_services and not is_auto_refresh:
            self.show_unmatched_services(unmatched_services)

        # print(f"Status update complete: {matched_count} services matched, {len(unmatched_services)} unmatched")

    def update_service_display(self, service_id):
        """Force update of a service's display elements"""
        widgets = self.service_widgets.get(service_id)
        if not widgets:
            return

        service = next((s for s in self.services_data if id(s) == service_id), None)
        if not service:
            return

        # print(f"Updating display for service {service.get('label')}")

        suspended = False
        if "status" in service:
            suspended = service["status"].get("suspended", False)
            # print(f"Service has status info - suspended: {suspended}")
        # else:
        # print("Service has no status info")

        if "status_indicator" in widgets and "status" in service:
            color = "yellow" if suspended else "green"
            # print(f"Setting LED color to {color} for {service.get('label')} (suspended={suspended})")

            if "led_id" in widgets:
                widgets["status_indicator"].itemconfig(widgets["led_id"], fill=color)
                # print(f"Updated LED color to {color}")
            # else:
            # print(f"WARNING: No led_id found in widgets for {service.get('label')}")

            if "status_tooltip" in widgets:
                status_text = "Suspended" if suspended else "Active"
                if service["status"].get("conflict", False):
                    status_text += " (CONFLICT)"
                widgets["status_tooltip"].configure(text=status_text)
                # print(f"Updated tooltip text to: {status_text}")

        if "uuid" in service and service["uuid"]:
            uuid = service["uuid"]
            has_conflict = service.get("status", {}).get("conflict", False)

            if "uuid_entry" in widgets:
                widgets["uuid_frame"].destroy()
                del widgets["uuid_frame"]
                del widgets["uuid_entry"]
                del widgets["uuid_var"]

                uuid_label = ttk.Label(
                    widgets["frame"],
                    text=f"UUID: {uuid}" + (" (CONFLICT)" if has_conflict else ""),
                    font=("TkDefaultFont", 8),
                    foreground="red" if has_conflict else "black",
                )
                uuid_label.grid(row=1, column=0, sticky="w", padx=25)
                widgets["uuid_label"] = uuid_label
            elif "uuid_label" in widgets:
                if has_conflict:
                    widgets["uuid_label"].config(
                        text=f"UUID: {uuid} (CONFLICT)", foreground="red"
                    )
                else:
                    widgets["uuid_label"].config(
                        text=f"UUID: {uuid}", foreground="black"
                    )
                widgets["uuid_label"].grid(row=1, column=0, sticky="w", padx=25)

            # print(f"Updated UUID label for {service.get('label')}: {uuid}")

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
            uuid = service.get("uuid", "Unknown UUID")
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
                        files_loaded += 1
                        # print( f"Successfully loaded {len(services)} services from: {filepath}")
                        success = True
                        break
                    # else:
                    # print(f"No services found in {filepath}")
                except Exception as e:
                    import traceback

                    # print(f"Error processing file {filepath}: {str(e)}")
                    traceback.print_exc()

            if not success:
                print(f"Failed to load from any path variation of: {filepath_input}")

        # print(f"Total services found: {len(self.services_data)}")
        self.display_services()

        if files_loaded == 0:
            self.log_error("No CloudI config files could be loaded")

    def apply_filters(self, *args):
        if hasattr(self, "services_data"):
            self.display_services()

    def display_services(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        self.service_widgets = {}

        if not self.services_data:
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

        header_frame = ttk.Frame(self.scrollable_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(
            header_frame, text="Service", width=40, font=("TkDefaultFont", 9, "bold")
        ).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        for _ in range(6):
            ttk.Label(header_frame, text="", width=11).pack(side=tk.LEFT, padx=2)

        ttk.Label(
            header_frame, text="Status", width=6, font=("TkDefaultFont", 9, "bold")
        ).pack(side=tk.LEFT, padx=2)

        separator = ttk.Separator(self.scrollable_frame, orient="horizontal")
        separator.pack(fill=tk.X, padx=5, pady=2)

        for idx, service in enumerate(filtered_services):
            row_container = ttk.Frame(self.scrollable_frame)
            row_container.pack(fill=tk.X, padx=5, pady=0)

            service_frame = ttk.Frame(row_container)
            service_frame.pack(fill=tk.X, pady=1)
            service_frame.columnconfigure(0, weight=1)

            label = ttk.Label(
                service_frame,
                text=f"{idx+1}. {service.get('label', 'Unknown')} ({service.get('prefix', 'unknown')})",
                width=40,
            )
            label.grid(row=0, column=0, sticky="ew", padx=5)

            tooltip_text = service.get("original_entry", "No original entry available")
            # TODO: fix tooltip content
            # self.create_tooltip(label, tooltip_text)

            service_id = id(service)
            self.service_widgets[service_id] = {}

            self.service_widgets[service_id]["frame"] = service_frame
            self.service_widgets[service_id]["label"] = label

            if "uuid" in service and service["uuid"]:
                uuid_label = ttk.Label(
                    service_frame,
                    text=f"UUID: {service['uuid']}",
                    font=("TkDefaultFont", 8),
                )
                uuid_label.grid(row=1, column=0, sticky="w", padx=25)
                self.service_widgets[service_id]["uuid_label"] = uuid_label
            else:
                uuid_frame = tk.Frame(service_frame)
                uuid_frame.grid(row=1, column=0, sticky="w", padx=25)

                ttk.Label(uuid_frame, text="UUID: ", font=("TkDefaultFont", 8)).pack(
                    side=tk.LEFT
                )

                uuid_var = tk.StringVar(value="")
                uuid_entry = ttk.Entry(
                    uuid_frame,
                    textvariable=uuid_var,
                    width=36,
                    font=("TkDefaultFont", 8),
                )
                uuid_entry.pack(side=tk.LEFT)

                self.service_widgets[service_id]["uuid_frame"] = uuid_frame
                self.service_widgets[service_id]["uuid_entry"] = uuid_entry
                self.service_widgets[service_id]["uuid_var"] = uuid_var

                def update_uuid(name, index, mode, s=service, var=uuid_var):
                    s["uuid"] = var.get()

                uuid_var.trace_add("write", update_uuid)

            buttons_frame = ttk.Frame(service_frame)
            buttons_frame.grid(row=0, column=1, sticky="e")

            subscriptions_btn = ttk.Button(
                buttons_frame,
                text="Subscriptions",
                command=lambda s=service: self.show_subscriptions(s),
            )
            subscriptions_btn.pack(side=tk.LEFT, padx=2)

            status_btn = ttk.Button(
                buttons_frame,
                text="Status",
                command=lambda s=service: self.show_status(s),
            )
            status_btn.pack(side=tk.LEFT, padx=2)

            remove_btn = ttk.Button(
                buttons_frame,
                text="Remove",
                command=lambda s=service: self.remove_service(s),
            )
            remove_btn.pack(side=tk.LEFT, padx=2)

            add_btn = ttk.Button(
                buttons_frame, text="Add", command=lambda s=service: self.add_service(s)
            )
            add_btn.pack(side=tk.LEFT, padx=2)

            suspend_btn = ttk.Button(
                buttons_frame,
                text="Suspend",
                command=lambda s=service: self.suspend_service(s),
            )
            suspend_btn.pack(side=tk.LEFT, padx=2)

            resume_btn = ttk.Button(
                buttons_frame,
                text="Resume",
                command=lambda s=service: self.resume_service(s),
            )
            resume_btn.pack(side=tk.LEFT, padx=2)

            status_frame = tk.Frame(buttons_frame, width=20, height=20)
            status_frame.pack(side=tk.LEFT, padx=(5, 2))

            status_indicator = tk.Canvas(
                status_frame,
                width=16,
                height=16,
                bg=self.winfo_toplevel()["bg"],
                highlightthickness=0,
            )
            status_indicator.pack()

            led_color = "gray"
            led_id = status_indicator.create_oval(
                2, 2, 14, 14, fill=led_color, outline="black"
            )

            self.service_widgets[service_id]["status_indicator"] = status_indicator
            self.service_widgets[service_id]["led_id"] = led_id

            status_tooltip_text = "Unknown status"
            if "status" in service:
                status_tooltip_text = (
                    "Active"
                    if not service["status"].get("suspended", False)
                    else "Suspended"
                )

            status_tooltip = tk.Label(
                status_frame.master,
                text=status_tooltip_text,
                background="#ffffe0",
                relief="solid",
                borderwidth=1,
            )
            status_tooltip.pack_forget()

            self.service_widgets[service_id]["status_tooltip"] = status_tooltip

            def on_enter(event, tooltip=status_tooltip, widget=status_indicator):
                x = widget.winfo_rootx()
                y = widget.winfo_rooty() + 20
                tooltip.place(x=x, y=y)

            def on_leave(event, tooltip=status_tooltip):
                tooltip.place_forget()

            status_indicator.bind("<Enter>", on_enter)
            status_indicator.bind("<Leave>", on_leave)

            separator = ttk.Separator(row_container, orient="horizontal")
            separator.pack(fill=tk.X, pady=2)

        self._update_scroll_region()

    def create_tooltip(self, widget, text):
        tooltip = tk.Label(
            self.winfo_toplevel(),
            text=text,
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            wraplength=600,
            justify="left",
        )
        tooltip.pack_forget()

        def on_enter(event):
            x = widget.winfo_rootx() + 25
            y = widget.winfo_rooty() + 25
            tooltip.place(x=x, y=y)

        def on_leave(event):
            tooltip.place_forget()

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

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

            # Create popup window to display results
            result_window = tk.Toplevel(self)
            result_window.title(title)
            result_window.geometry("600x400")
            result_window.transient(self.winfo_toplevel())

            # Create frame with scrollable text area
            frame = ttk.Frame(result_window, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            # Add status code and timestamp
            ttk.Label(
                frame,
                text=f"Status: {response.status_code} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ).pack(anchor="w", pady=(0, 10))

            # Create text widget with scrollbars
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

                # Try to format if it's JSON
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

            # Close button
            ttk.Button(frame, text="Close", command=result_window.destroy).pack(
                pady=(10, 0)
            )

            # If this was a suspend or resume action, update the service status
            if "suspend" in url or "resume" in url:
                self.after(1000, self.update_service_status)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform action: {str(e)}")

    def remove_service(self, service):
        messagebox.showinfo("Remove", f"Remove service {service['label']}")

    def add_service(self, service):
        messagebox.showinfo("Add", f"Add service like {service['label']}")

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
