"""Dark, local-only Tkinter dashboard."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from analyser import PasswordAnalysis, analyze_password
from generator import generate_passphrase, generate_passwords


class PasswordApp:
    """Application window and event handlers."""

    BG = "#101820"
    PANEL = "#182630"
    PANEL_ALT = "#20333f"
    TEXT = "#e8f0f3"
    MUTED = "#9bb0bb"
    ACCENT = "#38d9c4"
    RED = "#ff647c"
    YELLOW = "#ffc857"
    GREEN = "#39d9a5"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Password Strength Analyser & Generator")
        self.root.geometry("1020x760")
        self.root.minsize(820, 650)
        self.root.configure(bg=self.BG)
        self._analysis_job: str | None = None
        self._closing = False
        self._style()
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=self.BG)
        style.configure("Panel.TFrame", background=self.PANEL)
        style.configure("TLabel", background=self.BG, foreground=self.TEXT)
        style.configure("Panel.TLabel", background=self.PANEL, foreground=self.TEXT)
        style.configure("Muted.TLabel", background=self.PANEL, foreground=self.MUTED)
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 21), foreground=self.TEXT)
        style.configure("Section.TLabel", font=("Segoe UI Semibold", 12), foreground=self.ACCENT)
        style.configure("TButton", background=self.PANEL_ALT, foreground=self.TEXT, padding=(12, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#2c4856")])
        style.configure("Accent.TButton", background=self.ACCENT, foreground="#09221f", font=("Segoe UI Semibold", 10))
        style.map("Accent.TButton", background=[("active", "#69ead8")])
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.PANEL, foreground=self.MUTED, padding=(18, 10))
        style.map("TNotebook.Tab", background=[("selected", self.PANEL_ALT)], foreground=[("selected", self.ACCENT)])
        style.configure("TCheckbutton", background=self.PANEL, foreground=self.TEXT)
        style.map("TCheckbutton", background=[("active", self.PANEL)])
        style.configure("TEntry", fieldbackground=self.PANEL_ALT, foreground=self.TEXT, insertcolor=self.TEXT)
        style.configure("Horizontal.TProgressbar", troughcolor=self.PANEL_ALT, background=self.ACCENT, thickness=12)

    def _build(self) -> None:
        shell = ttk.Frame(self.root, padding=(28, 22))
        shell.pack(fill="both", expand=True)
        header = ttk.Frame(shell)
        header.pack(fill="x", pady=(0, 18))
        ttk.Label(header, text="PASSWORD LAB", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Analyse locally. Generate securely. Nothing is saved or sent.",
            foreground=self.MUTED,
        ).pack(anchor="w", pady=(3, 0))

        self.tabs = ttk.Notebook(shell)
        self.tabs.pack(fill="both", expand=True)
        self.analyser_tab = ttk.Frame(self.tabs, padding=18)
        self.generator_tab = ttk.Frame(self.tabs, padding=18)
        self.phrase_tab = ttk.Frame(self.tabs, padding=18)
        self.tabs.add(self.analyser_tab, text="  ANALYSE  ")
        self.tabs.add(self.generator_tab, text="  PASSWORD GENERATOR  ")
        self.tabs.add(self.phrase_tab, text="  PASSPHRASE  ")
        self._build_analyser()
        self._build_generator()
        self._build_passphrase()
        ttk.Label(
            shell,
            text="Privacy first · Passwords are processed in memory only",
            foreground=self.MUTED,
        ).pack(anchor="w", pady=(14, 0))

    def _panel(self, parent: ttk.Frame, **kwargs: object) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=16, **kwargs)
        return frame

    def _checkbox(self, parent: tk.Misc, text: str, variable: tk.BooleanVar) -> tk.Checkbutton:
        label = tk.StringVar()

        def update_label(*_: object) -> None:
            marker = "✓" if variable.get() else "□"
            label.set(f"{marker}  {text}")

        update_label()
        variable.trace_add("write", update_label)
        return tk.Checkbutton(
            parent,
            textvariable=label,
            variable=variable,
            indicatoron=False,
            command=update_label,
            background=self.PANEL,
            foreground=self.TEXT,
            activebackground=self.PANEL,
            activeforeground=self.ACCENT,
            selectcolor=self.PANEL_ALT,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=4,
            pady=3,
            anchor="w",
            font=("Segoe UI", 10),
        )

    def _build_analyser(self) -> None:
        tab = self.analyser_tab
        tab.columnconfigure(0, weight=3)
        tab.columnconfigure(1, weight=2)
        tab.rowconfigure(2, weight=1)
        input_panel = self._panel(tab)
        input_panel.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        ttk.Label(input_panel, text="Password to assess", style="Section.TLabel").pack(anchor="w")
        entry_row = ttk.Frame(input_panel, style="Panel.TFrame")
        entry_row.pack(fill="x", pady=(10, 4))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(entry_row, textvariable=self.password_var, show="•", font=("Consolas", 13))
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_checkbox = self._checkbox(entry_row, "Show", self.show_password_var)
        self.show_checkbox.configure(command=self._toggle_visibility)
        self.show_checkbox.pack(side="left", padx=(12, 0))
        ttk.Button(input_panel, text="Analyse password", style="Accent.TButton", command=self._analyse_now).pack(anchor="e", pady=(8, 0))
        self.password_var.trace_add("write", self._schedule_analysis)

        score_panel = self._panel(tab)
        score_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 7), pady=(0, 14))
        ttk.Label(score_panel, text="STRENGTH SCORE", style="Section.TLabel").pack(anchor="w")
        score_line = ttk.Frame(score_panel, style="Panel.TFrame")
        score_line.pack(fill="x", pady=(12, 6))
        self.score_label = ttk.Label(score_line, text="—", style="Panel.TLabel", font=("Segoe UI Semibold", 27))
        self.score_label.pack(side="left")
        self.rating_label = ttk.Label(score_line, text="Enter a password", style="Panel.TLabel", foreground=self.MUTED)
        self.rating_label.pack(side="left", padx=(12, 0), pady=(8, 0))
        self.progress = ttk.Progressbar(score_panel, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(3, 10))
        self.entropy_label = ttk.Label(score_panel, text="Estimated entropy: —", style="Muted.TLabel")
        self.entropy_label.pack(anchor="w")
        self.score_breakdown = ttk.Label(score_panel, text="Category points: —", style="Muted.TLabel", wraplength=430, justify="left")
        self.score_breakdown.pack(anchor="w", pady=(7, 0))

        checklist_panel = self._panel(tab)
        checklist_panel.grid(row=1, column=1, sticky="nsew", padx=(7, 0), pady=(0, 14))
        ttk.Label(checklist_panel, text="SECURITY CHECKLIST", style="Section.TLabel").pack(anchor="w")
        self.checklist_text = tk.Text(checklist_panel, height=8, wrap="word", bg=self.PANEL, fg=self.TEXT, relief="flat", font=("Segoe UI", 10), state="disabled")
        self.checklist_text.pack(fill="both", expand=True, pady=(8, 0))

        feedback = ttk.Frame(tab)
        feedback.grid(row=2, column=0, columnspan=2, sticky="nsew")
        feedback.columnconfigure(0, weight=1)
        feedback.columnconfigure(1, weight=1)
        self.weakness_text = self._feedback_box(feedback, "DETECTED WEAKNESSES", 0)
        self.advice_text = self._feedback_box(feedback, "RISKS & IMPROVEMENTS", 1)

    def _feedback_box(self, parent: ttk.Frame, title: str, column: int) -> tk.Text:
        panel = self._panel(parent)
        panel.grid(row=0, column=column, sticky="nsew", padx=(0, 7) if column == 0 else (7, 0))
        ttk.Label(panel, text=title, style="Section.TLabel").pack(anchor="w")
        text = tk.Text(panel, height=9, wrap="word", bg=self.PANEL, fg=self.TEXT, relief="flat", font=("Segoe UI", 10), state="disabled")
        text.pack(fill="both", expand=True, pady=(8, 0))
        return text

    def _build_generator(self) -> None:
        tab = self.generator_tab
        tab.columnconfigure(0, weight=1)
        settings = self._panel(tab)
        settings.pack(fill="x")
        ttk.Label(settings, text="CUSTOM PASSWORD", style="Section.TLabel").pack(anchor="w")
        fields = ttk.Frame(settings, style="Panel.TFrame")
        fields.pack(fill="x", pady=(14, 10))
        self.length_var = tk.IntVar(value=20)
        self.count_var = tk.IntVar(value=5)
        ttk.Label(fields, text="Length (8–64)", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(fields, from_=8, to=64, textvariable=self.length_var, width=8).grid(row=0, column=1, padx=(8, 25), sticky="w")
        ttk.Label(fields, text="Suggestions (1–10)", style="Panel.TLabel").grid(row=0, column=2, sticky="w")
        ttk.Spinbox(fields, from_=1, to=10, textvariable=self.count_var, width=8).grid(row=0, column=3, padx=(8, 0), sticky="w")
        self.category_vars = {
            "uppercase": tk.BooleanVar(value=True),
            "lowercase": tk.BooleanVar(value=True),
            "numbers": tk.BooleanVar(value=True),
            "symbols": tk.BooleanVar(value=True),
        }
        category_row = ttk.Frame(settings, style="Panel.TFrame")
        category_row.pack(fill="x", pady=(2, 8))
        for label, key in (("Uppercase", "uppercase"), ("Lowercase", "lowercase"), ("Numbers", "numbers"), ("Symbols", "symbols")):
            self._checkbox(category_row, label, self.category_vars[key]).pack(side="left", padx=(0, 14))
        self.exclude_var = tk.BooleanVar(value=True)
        self._checkbox(settings, "Exclude confusing characters (O, 0, l, 1)", self.exclude_var).pack(anchor="w")
        ttk.Button(settings, text="Generate secure passwords", style="Accent.TButton", command=self._generate).pack(anchor="e", pady=(12, 0))

        output = self._panel(tab)
        output.pack(fill="both", expand=True, pady=(14, 0))
        ttk.Label(output, text="PASSWORD SUGGESTIONS", style="Section.TLabel").pack(anchor="w")
        self.generated_list = tk.Listbox(output, height=11, bg=self.PANEL_ALT, fg=self.TEXT, selectbackground="#28665f", relief="flat", font=("Consolas", 12), activestyle="none")
        self.generated_list.pack(fill="both", expand=True, pady=(10, 10))
        ttk.Button(output, text="Copy selected password", command=self._copy_selected).pack(anchor="e")

    def _build_passphrase(self) -> None:
        panel = self._panel(self.phrase_tab)
        panel.pack(fill="x")
        ttk.Label(panel, text="MEMORABLE PASSPHRASE", style="Section.TLabel").pack(anchor="w")
        controls = ttk.Frame(panel, style="Panel.TFrame")
        controls.pack(fill="x", pady=(14, 10))
        self.word_count_var = tk.IntVar(value=5)
        self.separator_var = tk.StringVar(value="-")
        ttk.Label(controls, text="Words (3–10)", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(controls, from_=3, to=10, textvariable=self.word_count_var, width=7).grid(row=0, column=1, padx=(8, 22))
        ttk.Label(controls, text="Separator", style="Panel.TLabel").grid(row=0, column=2, sticky="w")
        ttk.Entry(controls, textvariable=self.separator_var, width=7).grid(row=0, column=3, padx=(8, 18))
        self.capitalize_var = tk.BooleanVar(value=False)
        self.add_number_var = tk.BooleanVar(value=False)
        self._checkbox(controls, "Capitalize words", self.capitalize_var).grid(row=0, column=4, padx=(0, 12))
        self._checkbox(controls, "Add number", self.add_number_var).grid(row=0, column=5)
        ttk.Button(panel, text="Generate passphrase", style="Accent.TButton", command=self._generate_phrase).pack(anchor="e")
        result = self._panel(self.phrase_tab)
        result.pack(fill="x", pady=(14, 0))
        ttk.Label(result, text="YOUR PASSPHRASE", style="Section.TLabel").pack(anchor="w")
        self.phrase_var = tk.StringVar()
        phrase_entry = ttk.Entry(result, textvariable=self.phrase_var, font=("Consolas", 14), state="readonly")
        phrase_entry.pack(fill="x", pady=(10, 12), ipady=8)
        ttk.Button(result, text="Copy passphrase", command=self._copy_phrase).pack(anchor="e")
        ttk.Label(
            self.phrase_tab,
            text="Words are selected independently with secrets from a built-in local word list. Use a unique phrase for each account.",
            foreground=self.MUTED,
            wraplength=780,
        ).pack(anchor="w", pady=(15, 0))

    def _toggle_visibility(self) -> None:
        self.password_entry.configure(show="" if self.show_password_var.get() else "•")

    def _schedule_analysis(self, *_: object) -> None:
        if self._closing:
            return
        if self._analysis_job is not None:
            self.root.after_cancel(self._analysis_job)
        self._analysis_job = self.root.after(180, self._analyse_now)

    def _analyse_now(self) -> None:
        self._analysis_job = None
        password = self.password_var.get()
        result = analyze_password(password)
        if not password:
            self.score_label.configure(text="—")
            self.rating_label.configure(text="Enter a password", foreground=self.MUTED)
            self.progress["value"] = 0
            self.entropy_label.configure(text="Estimated entropy: —")
            self.score_breakdown.configure(text="Category points: —")
            self._set_text(self.checklist_text, "Type a password to see the checklist.")
            self._set_text(self.weakness_text, "No password entered.")
            self._set_text(self.advice_text, "Your password stays in this app.")
            return
        self._render_analysis(result)

    def _render_analysis(self, result: PasswordAnalysis) -> None:
        color = self.GREEN if result.score >= 61 else self.YELLOW if result.score >= 41 else self.RED
        self.score_label.configure(text=f"{result.score}/100")
        self.rating_label.configure(text=result.rating, foreground=color)
        self.progress["value"] = result.score
        self.entropy_label.configure(text=f"Estimated entropy: {result.entropy_bits} bits (approximate)")
        breakdown = "  ·  ".join(f"{name.title()}: {points}" for name, points in result.category_scores.items())
        self.score_breakdown.configure(text=breakdown)
        checklist = "\n".join(f"{'✓' if passed else '○'}  {label}" for label, passed in result.checklist.items())
        self._set_text(self.checklist_text, checklist)
        self._set_text(self.weakness_text, "\n".join(f"•  {item}" for item in result.weaknesses) or "No common weaknesses detected.")
        advice = ["Risks", *[f"•  {item}" for item in result.risks], "", "Recommendations", *[f"•  {item}" for item in result.recommendations]]
        self._set_text(self.advice_text, "\n".join(advice))

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _generate(self) -> None:
        try:
            passwords = generate_passwords(
                count=self.count_var.get(),
                length=self.length_var.get(),
                uppercase=self.category_vars["uppercase"].get(),
                lowercase=self.category_vars["lowercase"].get(),
                numbers=self.category_vars["numbers"].get(),
                symbols=self.category_vars["symbols"].get(),
                exclude_ambiguous=self.exclude_var.get(),
            )
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Cannot generate passwords", str(error), parent=self.root)
            return
        self.generated_list.delete(0, "end")
        for password in passwords:
            self.generated_list.insert("end", password)
        self.generated_list.selection_set(0)

    def _copy_selected(self) -> None:
        selection = self.generated_list.curselection()
        if not selection:
            messagebox.showinfo("Nothing to copy", "Generate and select a password first.", parent=self.root)
            return
        self._copy_text(self.generated_list.get(selection[0]))

    def _generate_phrase(self) -> None:
        try:
            phrase = generate_passphrase(
                self.word_count_var.get(),
                separator=self.separator_var.get(),
                capitalize=self.capitalize_var.get(),
                add_number=self.add_number_var.get(),
            )
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Cannot generate passphrase", str(error), parent=self.root)
            return
        self.phrase_var.set(phrase)

    def _copy_phrase(self) -> None:
        if self.phrase_var.get():
            self._copy_text(self.phrase_var.get())
        else:
            messagebox.showinfo("Nothing to copy", "Generate a passphrase first.", parent=self.root)

    def _copy_text(self, value: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.root.update()
        except tk.TclError as error:
            messagebox.showerror("Clipboard unavailable", str(error), parent=self.root)
            return
        messagebox.showinfo("Copied", "Copied to clipboard. Clipboard contents may remain available to other apps.", parent=self.root)

    def _close(self) -> None:
        self._closing = True
        if self._analysis_job is not None:
            self.root.after_cancel(self._analysis_job)
        self.password_var.set("")
        self.generated_list.delete(0, "end")
        self.phrase_var.set("")
        self.root.destroy()


def run_app() -> None:
    """Launch the desktop application."""
    root = tk.Tk()
    PasswordApp(root)
    root.mainloop()
