import os
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Create the projects directory if it doesn't exist
PROJECTS_DIR = "projects"
os.makedirs(PROJECTS_DIR, exist_ok=True)

# Color scheme
BG_COLOR = "#000000"  # Black background
TEXT_COLOR = "#FFFFFF"  # White text
BUTTON_COLOR = "#333333"  # Dark gray buttons
SAVE_BUTTON_COLOR = "#006400"  # Dark green Save button
QUIT_BUTTON_COLOR = "#FF0000"  # Red Quit button

class DiaryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Diary App")
        self.root.attributes("-fullscreen", True)
        self.root.bind("<Escape>", self.exit_fullscreen)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.config(bg=BG_COLOR)

        self.setup_buttons()
        self.setup_project_list()
        self.setup_writing_space()

        self.current_project = None
        self.current_project_key = None

    def exit_fullscreen(self, event=None):
        self.root.attributes("-fullscreen", False)

    def on_close(self):
        if self.current_project:
            self.save_project()
        self.root.destroy()

    def setup_buttons(self):
        button_frame = tk.Frame(self.root, bg=BG_COLOR)
        button_frame.pack(side=tk.TOP, fill=tk.X)

        create_button = tk.Button(
            button_frame, text="Create", command=self.create_project, bg=BUTTON_COLOR, fg=TEXT_COLOR
        )
        create_button.pack(side=tk.LEFT, padx=5, pady=5)

        open_button = tk.Button(
            button_frame, text="Open", command=self.open_selected_project, bg=BUTTON_COLOR, fg=TEXT_COLOR
        )
        open_button.pack(side=tk.LEFT, padx=5, pady=5)

        delete_button = tk.Button(
            button_frame, text="Delete", command=self.delete_project, bg=BUTTON_COLOR, fg=TEXT_COLOR
        )
        delete_button.pack(side=tk.LEFT, padx=5, pady=5)

        rename_button = tk.Button(
            button_frame, text="Rename", command=self.rename_project, bg=BUTTON_COLOR, fg=TEXT_COLOR
        )
        rename_button.pack(side=tk.LEFT, padx=5, pady=5)

        quit_button = tk.Button(
            button_frame, text="Quit", command=self.on_close, bg=QUIT_BUTTON_COLOR, fg=TEXT_COLOR
        )
        quit_button.pack(side=tk.RIGHT, padx=10)

        self.save_button = tk.Button(
            button_frame, text="Save", command=self.save_project, bg=SAVE_BUTTON_COLOR, fg=TEXT_COLOR
        )
        self.save_button.pack(side=tk.RIGHT, padx=5, pady=5)
        self.save_button.config(state=tk.DISABLED)

    def setup_project_list(self):
        project_frame = tk.Frame(self.root, bg=BG_COLOR)
        project_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.project_listbox = tk.Listbox(
            project_frame, fg=TEXT_COLOR, bg=BG_COLOR, selectbackground=BUTTON_COLOR, selectforeground=TEXT_COLOR
        )
        self.project_listbox.pack(fill=tk.BOTH, expand=True)

        self.project_listbox.bind("<<ListboxSelect>>", self.select_project)

        self.load_projects()

    def load_projects(self):
        self.project_listbox.delete(0, tk.END)
        projects = os.listdir(PROJECTS_DIR)
        for project in projects:
            self.project_listbox.insert(tk.END, project)

    def select_project(self, event=None):
        selected_project = self.project_listbox.get(tk.ACTIVE)
        if selected_project:
            self.current_project = selected_project
            self.current_project_key = None
            self.enable_writing_space()

    def enable_writing_space(self):
        self.text_widget.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)

    def disable_writing_space(self):
        self.text_widget.delete("1.0", tk.END)
        self.text_widget.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

    def setup_writing_space(self):
        self.writing_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.writing_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.text_widget = tk.Text(
            self.writing_frame, fg=TEXT_COLOR, bg=BG_COLOR, insertbackground=TEXT_COLOR,
            selectbackground=BUTTON_COLOR, selectforeground=TEXT_COLOR
        )
        self.text_widget.pack(fill=tk.BOTH, expand=True)

        self.disable_writing_space()

    def create_project(self):
        project_name = simpledialog.askstring("Create Project", "Enter project name:", parent=self.root)
        if project_name:
            key = simpledialog.askstring("Create Project", "Enter encryption password:", show="*", parent=self.root)
            if not key:
                messagebox.showerror("Error", "Encryption password is required.")
                return

            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=100000,
                salt=salt,
                length=32
            )
            key = base64.urlsafe_b64encode(kdf.derive(key.encode()))

            cipher_suite = Fernet(key)

            project_file = os.path.join(PROJECTS_DIR, project_name)
            if os.path.exists(project_file):
                messagebox.showerror("Error", "Project with the same name already exists.")
                return

            with open(project_file, "wb") as encrypted_file:
                encrypted_content = cipher_suite.encrypt(b"")
                encrypted_file.write(salt + encrypted_content)
            self.load_projects()

    def open_selected_project(self):
        if self.current_project:
            self.open_project()

    def open_project(self):
        if self.current_project:
            project_file = os.path.join(PROJECTS_DIR, self.current_project)
            if not os.path.exists(project_file):
                messagebox.showerror("Error", "Project file not found.")
                return

            if self.current_project_key is None:
                key = simpledialog.askstring("Open Project", "Enter encryption password:", show="*", parent=self.root)
                if not key:
                    messagebox.showerror("Error", "Encryption password is required.")
                    return

                with open(project_file, "rb") as encrypted_file:
                    salt = encrypted_file.read(16)
                    encrypted_content = encrypted_file.read()

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    iterations=100000,
                    salt=salt,
                    length=32
                )
                key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
                self.current_project_key = key

            cipher_suite = Fernet(self.current_project_key)

            try:
                decrypted_content = cipher_suite.decrypt(encrypted_content).decode()
            except Exception as e:
                messagebox.showerror("Error", "Invalid encryption password.")
                return

            self.text_widget.delete("1.0", tk.END)
            self.text_widget.insert("1.0", decrypted_content)

    def delete_project(self):
        selected_project = self.project_listbox.get(tk.ACTIVE)
        if selected_project:
            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{selected_project}'?")
            if confirm:
                project_file = os.path.join(PROJECTS_DIR, selected_project)
                os.remove(project_file)
                self.load_projects()

    def rename_project(self):
        selected_project = self.project_listbox.get(tk.ACTIVE)
        if selected_project:
            new_name = simpledialog.askstring("Rename Project", "Enter new project name:", parent=self.root)
            if new_name:
                project_file = os.path.join(PROJECTS_DIR, selected_project)
                new_project_file = os.path.join(PROJECTS_DIR, new_name)
                os.rename(project_file, new_project_file)
                self.load_projects()

    def save_project(self):
        if self.current_project and self.current_project_key:
            project_file = os.path.join(PROJECTS_DIR, self.current_project)
            if not os.path.exists(project_file):
                messagebox.showerror("Error", "Project file not found.")
                return

            with open(project_file, "rb") as encrypted_file:
                salt = encrypted_file.read(16)
                encrypted_content = encrypted_file.read()

            cipher_suite = Fernet(self.current_project_key)

            new_content = self.text_widget.get("1.0", tk.END).encode()
            encrypted_content = cipher_suite.encrypt(new_content)
            with open(project_file, "wb") as encrypted_file:
                encrypted_file.write(salt + encrypted_content)
            messagebox.showinfo("Success", "Project saved successfully.")

def main():
    root = tk.Tk()
    root.config(bg=BG_COLOR)
    app = DiaryApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
