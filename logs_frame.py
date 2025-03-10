import tkinter as tk
from tkinter import ttk
from datetime import datetime


class LogsFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.logs = []
        self.create_widgets()

    def create_widgets(self):
        """Create the UI for logs display"""
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        logs_panel = ttk.LabelFrame(self, text="System Logs")
        logs_panel.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        logs_panel.columnconfigure(0, weight=1)
        logs_panel.rowconfigure(1, weight=1)

        filter_frame = tk.Frame(logs_panel)
        filter_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        filter_frame.columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="Filter:").grid(
            row=0, column=0, sticky="w", padx=(0, 5)
        )
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self.apply_filter)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var)
        filter_entry.grid(row=0, column=1, sticky="ew", padx=5)

        filter_types_frame = tk.Frame(filter_frame)
        filter_types_frame.grid(row=0, column=2, sticky="w", padx=5)

        self.show_errors_var = tk.BooleanVar(value=True)
        self.show_errors_var.trace("w", self.apply_filter)
        ttk.Checkbutton(
            filter_types_frame, text="Errors", variable=self.show_errors_var
        ).pack(side=tk.LEFT, padx=5)

        self.show_info_var = tk.BooleanVar(value=True)
        self.show_info_var.trace("w", self.apply_filter)
        ttk.Checkbutton(
            filter_types_frame, text="Info", variable=self.show_info_var
        ).pack(side=tk.LEFT, padx=5)

        self.show_warnings_var = tk.BooleanVar(value=True)
        self.show_warnings_var.trace("w", self.apply_filter)
        ttk.Checkbutton(
            filter_types_frame, text="Warnings", variable=self.show_warnings_var
        ).pack(side=tk.LEFT, padx=5)

        self.show_debug_var = tk.BooleanVar(value=False)
        self.show_debug_var.trace("w", self.apply_filter)
        ttk.Checkbutton(
            filter_types_frame, text="Debug", variable=self.show_debug_var
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(filter_types_frame, text="Clear Logs", command=self.clear_logs).pack(
            side=tk.LEFT, padx=(20, 5)
        )

        log_frame = ttk.Frame(logs_panel)
        log_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        h_scroll = tk.Scrollbar(log_frame, orient="horizontal")
        h_scroll.grid(row=1, column=0, sticky="ew")

        v_scroll = ttk.Scrollbar(log_frame)
        v_scroll.grid(row=0, column=1, sticky="ns")

        self.log_text = tk.Text(
            log_frame,
            wrap="none",
            bg="#f8f8f8",
            xscrollcommand=h_scroll.set,
            yscrollcommand=v_scroll.set,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.config(state="disabled")

        h_scroll.config(command=self.log_text.xview)
        v_scroll.config(command=self.log_text.yview)

        self.log_text.tag_configure("error", foreground="#aa0000")
        self.log_text.tag_configure("warning", foreground="#aa5500")
        self.log_text.tag_configure("info", foreground="#007700")
        self.log_text.tag_configure("debug", foreground="#555555")

    def add_log(self, message, level="info", timestamp=None):
        """Add a log entry to the system"""
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_entry = {"timestamp": timestamp, "level": level, "message": message}

        self.logs.append(log_entry)
        self.display_log_entry(log_entry)

    def display_log_entry(self, log_entry):
        """Display a single log entry if it meets filter criteria"""
        level = log_entry.get("level", "info").lower()
        if (
            level == "error"
            and not self.show_errors_var.get()
            or level == "warning"
            and not self.show_warnings_var.get()
            or level == "info"
            and not self.show_info_var.get()
            or level == "debug"
            and not self.show_debug_var.get()
        ):
            return

        if (
            self.filter_var.get()
            and self.filter_var.get().lower()
            not in log_entry.get("message", "").lower()
        ):
            return

        self.log_text.config(state="normal")

        # Format: [TIMESTAMP] [LEVEL] message
        log_text = f"[{log_entry.get('timestamp')}] [{level.upper()}] {log_entry.get('message')}\n"

        self.log_text.insert(tk.END, log_text, level)
        self.log_text.see(tk.END)

        self.log_text.config(state="disabled")

    def apply_filter(self, *args):
        """Apply filters to already loaded logs"""
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")

        for log_entry in self.logs:
            self.display_log_entry(log_entry)

    def clear_logs(self):
        """Clear all logs from the display and memory"""
        self.logs = []
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")

    def add_error(self, message):
        """Helper method to add an error log"""
        self.add_log(message, level="error")

    def add_warning(self, message):
        """Helper method to add a warning log"""
        self.add_log(message, level="warning")

    def add_info(self, message):
        """Helper method to add an info log"""
        self.add_log(message, level="info")

    def add_debug(self, message):
        """Helper method to add a debug log"""
        self.add_log(message, level="debug")
