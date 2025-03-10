import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import argparse
from rpc_frame import RPCFrame
from services_frame import ServicesFrame
from about_frame import AboutFrame
from logs_frame import LogsFrame


class TkLoudiApp(tk.Tk):
    def __init__(self, config_file="files/api.conf"):
        super().__init__()
        self.config_file = config_file
        self.config_data = self.load_config()
        self.title(self.config_data.get("title", "tkloudi"))
        self.load_icon()
        self.geometry("1200x800")
        self.create_widgets()

    def load_config(self):
        default_config = {
            "title": "tkloudi",
            "icon": "assets/icon.png",
            "default_api_paths": [
                "files/cloudi-api-paths.json",
            ],
            "servers": ["http://localhost:6464"],
            "cloudi_conf_files": ["files/cloudi_minimal.conf"],
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r") as f:
                    return json.load(f)
            else:
                os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
                with open(self.config_file, "w") as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            # print(f"Error loading config: {e}")
            return default_config

    def load_icon(self):
        icon_path = self.config_data.get("icon", "assets/icon.png")

        if os.path.exists(icon_path):
            try:
                icon_image = tk.PhotoImage(file=icon_path)
                self.iconphoto(True, icon_image)
                self.icon_image = icon_image
                # print(f"Icon loaded: {icon_path}")
            except Exception as e:
                print(f"Error loading icon: {e}")
        # else:
        # print(f"Icon file '{icon_path}' not found.")

    def create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.services_frame = ServicesFrame(self)
        self.notebook.add(self.services_frame, text="Services")

        self.rpc_frame = RPCFrame(self)
        self.notebook.add(self.rpc_frame, text="APIs")

        self.logs_frame = LogsFrame(self)
        self.notebook.add(self.logs_frame, text="Logs")

        self.about_frame = AboutFrame(self)
        self.notebook.add(self.about_frame, text="About")

    def log_message(self, message, level="info"):
        """Log a message to the logs frame"""
        if hasattr(self, "logs_frame"):
            self.logs_frame.add_log(message, level)

            if (
                self.notebook.index(self.notebook.select()) != 2
            ):  # Assuming Logs is tab index 2
                self.notebook.tab(2, text="*Logs*")
        # else:
        # print(f"[{level.upper()}] {message}")

    def log_error(self, message):
        self.log_message(message, "error")

    def log_warning(self, message):
        self.log_message(message, "warning")

    def log_info(self, message):
        self.log_message(message, "info")

    def log_debug(self, message):
        self.log_message(message, "debug")


def main():
    parser = argparse.ArgumentParser(description="tkloudi")
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="files/api.conf",
        help="Path to the configuration file",
    )
    args = parser.parse_args()

    app = TkLoudiApp(config_file=args.config)
    app.mainloop()


if __name__ == "__main__":
    main()
