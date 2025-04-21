import customtkinter as ctk
import sqlite3
import hashlib
import os
import datetime
from tkinter.font import Font  # Import Font from tkinter.font

# Database setup
DB_NAME = "todo_app.db"

def create_connection():
    """Creates a database connection."""
    conn = sqlite3.connect(DB_NAME)
    return conn

def create_tables():
    """Creates necessary tables if they don't exist."""
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task TEXT NOT NULL,
            description TEXT,
            due_date TEXT,
            priority TEXT,
            completed INTEGER DEFAULT 0,
            checked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    try:
        cursor.execute("SELECT checked FROM tasks LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE tasks ADD COLUMN checked INTEGER DEFAULT 0")
    try:
        cursor.execute("SELECT description FROM tasks LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE tasks ADD COLUMN description TEXT")

    conn.commit()
    conn.close()

create_tables()

# Login system
def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    """Registers a new user."""
    conn = create_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def login_user(username, password):
    """Logs in a user."""
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and result[1] == hash_password(password):
        return result[0]  # Return user ID
    return None

# Todo list application
class TodoApp:
    def __init__(self, root, user_id):
        self.root = root
        self.user_id = user_id
        self.root.title("Todo List")
        self.root.geometry("800x600")

        self.task_entry = ctk.CTkEntry(root, placeholder_text="Enter task")
        self.task_entry.pack(pady=10)

        self.description_entry = ctk.CTkEntry(root, placeholder_text="Enter description (optional)")
        self.description_entry.pack(pady=10)

        self.due_date_entry = ctk.CTkEntry(root, placeholder_text="Due Date")
        self.due_date_entry.pack(pady=10)

        self.priority_var = ctk.StringVar(value="Choose a Priority")  # Default prompt
        self.priority_menu = ctk.CTkOptionMenu(root, values=["Low", "Medium", "High"], variable=self.priority_var)
        self.priority_menu.pack(pady=10)

        # Create a frame to hold the buttons side by side
        self.button_frame = ctk.CTkFrame(root)
        self.button_frame.pack(pady=10)

        self.add_button = ctk.CTkButton(self.button_frame, text="Add Task", command=self.add_task)
        self.add_button.pack(side="left", padx=5)  # Use side="left" and padx

        self.delete_tasks_button = ctk.CTkButton(self.button_frame, text="Delete Tasks", command=self.delete_selected_tasks, fg_color="gray", state="disabled")
        self.delete_tasks_button.pack(side="left", padx=5)  # Use side="left" and padx

        self.task_list = ctk.CTkScrollableFrame(root)
        self.task_list.pack(pady=10, fill="both", expand=True)

        self.logout_button = ctk.CTkButton(root, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

        self.load_tasks()

        self.root.bind('<Return>', lambda event=None: self.add_task()) #bind enter to add task

    def add_task(self):
        """Adds a new task to the database and updates the UI."""
        task = self.task_entry.get()
        description = self.description_entry.get()
        due_date = self.due_date_entry.get()
        priority = self.priority_var.get()
        if task:
            conn = create_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO tasks (user_id, task, description, due_date, priority) VALUES (?, ?, ?, ?, ?)",
                            (self.user_id, task, description, due_date, priority))
            conn.commit()
            conn.close()
            self.task_entry.delete(0, ctk.END)
            self.description_entry.delete(0, ctk.END)
            self.due_date_entry.delete(0, ctk.END)
            self.priority_var.set("Choose a Priority") #reset priority after adding to default prompt
            self.load_tasks()

    def load_tasks(self):
        """Loads tasks from the database and displays them in the UI."""
        for widget in self.task_list.winfo_children():
            widget.destroy()

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, task, description, due_date, priority, completed, checked FROM tasks WHERE user_id = ?", (self.user_id,))
        tasks = cursor.fetchall()
        conn.close()

        self.task_checkboxes = {} # Dictionary to store task IDs and their corresponding checkboxes

        for task_id, task, description, due_date, priority, completed, checked in tasks:
            task_frame = ctk.CTkFrame(self.task_list)
            task_frame.pack(pady=5, fill="x")

            top_row = ctk.CTkFrame(task_frame, fg_color="transparent")
            top_row.pack(fill="x")

            priority_color = "green"  # Default to green (Low)
            if priority == "Medium":
                priority_color = "yellow"
            elif priority == "High":
                priority_color = "red"

            task_label_text = f"{task}"
            if due_date:
                task_label_text += f" (Due: {due_date})"
            
            task_label = ctk.CTkLabel(top_row, text=task_label_text, anchor="w", font=("Helvetica Rounded", 14), wraplength=600, justify="left")
            task_label.pack(side="left", padx=5, fill="x", expand=True)

            if priority and priority != "Choose a Priority":
                priority_label = ctk.CTkLabel(task_frame, text=f" (Priority: {priority})", text_color=priority_color, anchor="w", font=("Helvetica Rounded", 14))
                priority_label.pack(side="left")

            dropdown_var = ctk.StringVar(value="")
            priority_menu = ctk.CTkOptionMenu(
                top_row,
                values=["Priority: Low", "Priority: Medium", "Priority: High", "Edit Due Date", "Edit Task"],
                command=lambda p, tid=task_id: self.handle_dropdown(tid, p),
                variable=dropdown_var,
                width=0,
                fg_color=self.task_list.cget("fg_color"),
                button_color=self.task_list.cget("fg_color"),
                button_hover_color="#565B5E",
                dropdown_fg_color="#343638",
                dropdown_hover_color="#565B5E",
                dropdown_text_color="#DCE4EE",
            )
            priority_menu.pack(side="left", padx=5)

            checkbox_var = ctk.BooleanVar()
            checkbox = ctk.CTkCheckBox(top_row, text="", variable=checkbox_var, command=lambda tid=task_id, checkvar=checkbox_var: self.update_checked(tid, checkvar.get()))
            checkbox.pack(side="left", padx=5)
            self.task_checkboxes[task_id] = checkbox_var # Store checkbox variable in dictionary

            complete_button = ctk.CTkButton(task_frame, text="Complete", command=lambda tid=task_id, comp=completed, checkvar=checkbox_var: self.toggle_complete(tid, comp, checkvar))
            if completed:
                complete_button.configure(text="Uncomplete")
                checkbox_var.set(True) # Set checkbox to checked if task is completed
            else:
                checkbox_var.set(False)
            checkbox_var.set(checked) #set checkbox to correct value from database

            if description:
                description_label = ctk.CTkLabel(task_frame, text=f"Description: {description}", anchor="w", font=("Helvetica", 12), wraplength=600, justify="left")
                description_label.pack(anchor="w", padx=10, pady=(0, 5))

    def update_checked(self, task_id, checked_value):
        """Updates the checked status in the database."""
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET checked = ? WHERE id = ?", (int(checked_value), task_id))
        conn.commit()
        conn.close()
        self.update_delete_button_state()

    def delete_selected_tasks(self):
        """Deletes tasks with checked checkboxes."""
        tasks_to_delete = []
        for task_id, checkbox_var in self.task_checkboxes.items():
            if checkbox_var.get():
                tasks_to_delete.append(task_id)

        if tasks_to_delete:
            conn = create_connection()
            cursor = conn.cursor()
            for task_id in tasks_to_delete:
                cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            conn.close()
            self.load_tasks() # Reload tasks after deleting.

    def handle_dropdown(self, task_id, selected_option):
        """Handles dropdown selection, calling appropriate functions."""
        if selected_option in ["Priority: Low", "Priority: Medium", "Priority: High"]:
            self.change_priority(task_id, selected_option.split(": ")[1])
        elif selected_option == "Edit Due Date":
            self.open_due_date_dialog(task_id)
        elif selected_option == "Edit Task":
            self.open_edit_task_dialog(task_id)

    def change_priority(self, task_id, priority):
        """Changes the priority of a task in the database and updates the UI."""
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET priority = ? WHERE id = ?", (priority, task_id))
        conn.commit()
        conn.close()
        self.load_tasks()

    def toggle_complete(self, task_id, completed, checkvar):
        """Toggles a task's completion status in the database and updates the UI."""
        conn = create_connection()
        cursor = conn.cursor()
        if completed:
            cursor.execute("UPDATE tasks SET completed = 0 WHERE id = ?", (task_id,))
            checkvar.set(False)
        else:
            cursor.execute("UPDATE tasks SET completed = 1 WHERE id = ?", (task_id,))
            checkvar.set(True)
        conn.commit()
        conn.close()
        self.load_tasks()

    def open_due_date_dialog(self, task_id):
        """Opens a dialog to change the due date of a task."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Edit Due Date")
        dialog.geometry("300x150")
        dialog.lift()
        dialog.focus_force()
        dialog.grab_set()

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT due_date FROM tasks WHERE id = ?", (task_id,))
        current_due_date = cursor.fetchone()[0]
        conn.close()

        due_date_entry = ctk.CTkEntry(dialog, placeholder_text="Change Date", textvariable=ctk.StringVar(value=current_due_date if current_due_date else ""))
        due_date_entry.pack(pady=10)
        save_button = ctk.CTkButton(dialog, text="Save", command=lambda: self.update_due_date(task_id, due_date_entry.get(), dialog))
        save_button.pack(pady=10)
        dialog.bind('<Return>', lambda event=None, task_id = task_id, entry = due_date_entry, dialog = dialog: self.update_due_date(task_id, entry.get(), dialog)) #bind enter to save

    def update_due_date(self, task_id, new_due_date, dialog):
        """Updates the due date in the database and closes the dialog."""
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET due_date = ? WHERE id = ?", (new_due_date, task_id))
        conn.commit()
        conn.close()
        dialog.destroy()
        self.load_tasks()

    def open_edit_task_dialog(self, task_id):
        """Opens a dialog to edit the task."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Edit Task")
        dialog.geometry("300x150")
        dialog.lift()
        dialog.focus_force()
        dialog.grab_set()

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT task, description FROM tasks WHERE id = ?", (task_id,))
        task_text, description_text = cursor.fetchone()
        conn.close()

        task_entry = ctk.CTkEntry(dialog, placeholder_text="Edit Task", textvariable=ctk.StringVar(value=task_text))
        task_entry.pack(pady=10)

        description_entry = ctk.CTkEntry(dialog, placeholder_text="Edit Description", textvariable=ctk.StringVar(value=description_text if description_text else ""))
        description_entry.pack(pady=10)

        save_button = ctk.CTkButton(dialog, text="Save", command=lambda: self.update_task(task_id, task_entry.get(), description_entry.get(), dialog))
        save_button.pack(pady=10)

        dialog.bind('<Return>', lambda event=None, task_id = task_id, entry = task_entry, dialog = dialog: self.update_task(task_id, entry.get(), dialog)) #bind enter to save

    def update_task(self, task_id, new_task_text, new_description, dialog):
        """Updates the task text in the database and closes the dialog."""
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET task = ?, description = ? WHERE id = ?", (new_task_text, new_description, task_id))
        conn.commit()
        conn.close()
        dialog.destroy()
        self.load_tasks()

    def logout(self):
        self.root.destroy()
        root = ctk.CTk()
        LoginApp(root)
        root.mainloop()

    def update_delete_button_state(self):
        """Updates the state of the delete button based on checkbox selection."""
        checked_tasks = any(var.get() for var in self.task_checkboxes.values())
        if checked_tasks:
            self.delete_tasks_button.configure(state="normal", fg_color="red")
        else:
            self.delete_tasks_button.configure(state="disabled", fg_color="gray")

# Login/Register UI
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Register")
        self.root.geometry("450x450")

        self.title_label = ctk.CTkLabel(root, text="Login", font=("Helvetica Rounded", 26))
        self.title_label.pack(pady=10)

        self.username_entry = ctk.CTkEntry(root, placeholder_text="Username", width=160)
        self.username_entry.pack()

        self.password_entry = ctk.CTkEntry(root, placeholder_text="Password", show="*", width=160)
        self.password_entry.pack(pady=10)

        self.login_button = ctk.CTkButton(root, text="Login", command=self.login)
        self.login_button.pack(pady=5)

        self.register_button = ctk.CTkButton(root, text="Register", command=self.register)
        self.register_button.pack(pady=5)

        self.error_label = ctk.CTkLabel(root, text="", text_color="red", font=("Helvetica Rounded", 12))
        self.error_label.pack(pady=5)

        self.root.bind('<Return>', lambda event=None: self.login()) #bind enter button to login

    def login(self):
        """Handles user login."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_id = login_user(username, password)
        if user_id:
            self.root.destroy()
            todo_root = ctk.CTk()
            TodoApp(todo_root, user_id)
            todo_root.mainloop()
        else:
            self.error_label.configure(text="Invalid username or password")

    def register(self):
        """Handles user registration."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if register_user(username, password):
            self.error_label.configure(text="Registration successful")
        else:
            self.error_label.configure(text="Username already exists")

if __name__ == "__main__":
    root = ctk.CTk()
    LoginApp(root)
    root.mainloop()