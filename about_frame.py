import tkinter as tk
from tkinter import ttk
import webbrowser


class AboutFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Create the main content frame
        content_frame = ttk.Frame(self)
        content_frame.pack(expand=True, fill="both", padx=20, pady=20)

        # App title
        title_label = ttk.Label(
            content_frame, text="tkloudi", font=("TkDefaultFont", 24, "bold")
        )
        title_label.pack(pady=10)

        # Version
        version_label = ttk.Label(content_frame, text="Version 0.1.0")
        version_label.pack()

        # Description
        description = (
            "A CloudI service management and API testing tool.\n"
            "Designed to make working with CloudI services easier."
        )
        desc_label = ttk.Label(
            content_frame, text=description, wraplength=400, justify="center"
        )
        desc_label.pack(pady=20)

        # Credits
        credits_label = ttk.Label(
            content_frame,
            text="Created by Filipe Moraes",
            font=("TkDefaultFont", 10, "italic"),
        )
        credits_label.pack(pady=10)

        # GitHub tkcloudi link
        link_label = ttk.Label(
            content_frame, text="GitHub tkloudi", foreground="blue", cursor="hand2"
        )
        link_label.pack(pady=5)
        link_label.bind(
            "<Button-1>",
            lambda e: webbrowser.open("https://github.com/devfilipe/tkloudi"),
        )

        # GitHub CloudI link
        link_label = ttk.Label(
            content_frame, text="GitHub cloudi", foreground="blue", cursor="hand2"
        )
        link_label.pack(pady=5)
        link_label.bind(
            "<Button-1>", lambda e: webbrowser.open("https://github.com/cloudi/cloudi")
        )

        # License
        license_text = (
            "This software is licensed under the MIT License.\n" "© 2025 Filipe Moraes"
        )
        license_label = ttk.Label(content_frame, text=license_text, justify="center")
        license_label.pack(pady=20)
