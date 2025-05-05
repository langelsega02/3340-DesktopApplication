import customtkinter as ctk
import sqlite3
import hashlib
import sys
import os
import datetime
from tkinter.font import Font  # Import Font from tkinter.font
from tkinter import messagebox

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
            password TEXT NOT NULL,
            role TEXT DEFAULT 'receiver'
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
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'receiver'")
    except sqlite3.OperationalError:
        pass  # Column already exists
    try:
        cursor.execute("ALTER TABLE tasks ADD COLUMN receiver_id INTEGER")
    except sqlite3.OperationalError:
        pass  # already added
    try:
        cursor.execute("ALTER TABLE tasks ADD COLUMN assigner_id INTEGER")
    except sqlite3.OperationalError:
        pass

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
class ReciverApp():
    def __init__(self, root, user_id):
        self.root = root
        self.user_id = user_id
        self.root.title("Todo List")
        self.root.geometry("800x600")

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        username = self.load_username()
        self.user = ctk.StringVar(value= f"Welcome, {username}!")
        self.welcome_msg = ctk.CTkLabel(root, textvariable = self.user, font=("Helvetica Rounded", 20))
        self.welcome_msg.pack(anchor="w", padx=20, pady=(15,5))

        self.welcome_2 = ctk.CTkLabel(root, text="Here are your assigned tasks:" ,font=("Helvetica Rounded", 15))
        self.welcome_2.pack(anchor="w", padx=20, pady=5)

        self.task_list = ctk.CTkScrollableFrame(root)
        self.task_list.pack(pady=10, fill="both", expand=True)

        self.logout_button = ctk.CTkButton(root, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

        self.load_tasks()

    def on_closing(self):
        self.root.destroy()
        sys.exit(0)

    def load_username(self):
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (self.user_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else "User"

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

            if priority != "Choose Priority":
                priority_label = ctk.CTkLabel(task_frame, text=f" (Priority: {priority})", text_color=priority_color, anchor="w", font=("Helvetica Rounded", 14))
                priority_label.pack(side="left")

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
                description_label = ctk.CTkLabel(task_frame, text=f"Description: {description}", anchor="w", font=("Helvetica", 13), wraplength=400, justify="left")
                description_label.pack(anchor="w", padx=5)

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


    def update_checked(self, task_id, checked_value):
        """Updates the checked status in the database."""
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET checked = ? WHERE id = ?", (int(checked_value), task_id))
        conn.commit()
        conn.close()

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


    def logout(self):
        self.root.destroy()
        root = App()
        root.mainloop()

class TodoApp():
    def __init__(self, root, user_id):
        self.root = root
        self.user_id = user_id
        self.root.title("Todo List")
        self.root.geometry("800x600")

        self.entry_frame = ctk.CTkFrame(root, fg_color="transparent")
        self.entry_frame.pack(pady = 10)

        self.description_entry = ctk.CTkEntry(self.entry_frame, height = 65, width = 200, placeholder_text="Enter description (optional)")
        self.description_entry.pack(padx=5, side = "right")
        
        self.task_entry = ctk.CTkEntry(self.entry_frame, placeholder_text="Enter task")
        self.task_entry.pack(padx=5, pady = 5)

        self.due_date_entry = ctk.CTkEntry(self.entry_frame, placeholder_text="Due Date")
        self.due_date_entry.pack(padx=5, pady = 5)

        self.dropdown_frame = ctk.CTkFrame(root,fg_color="transparent")
        self.dropdown_frame.pack()

        self.priority_var = ctk.StringVar(value="Choose Priority")  # Default prompt
        self.priority_menu = ctk.CTkOptionMenu(self.dropdown_frame, values=["Low", "Medium", "High"], variable=self.priority_var)
        self.priority_menu.pack(pady=5, padx = 5, side = "left")

        self.choose_receiver_button = ctk.CTkButton(self.dropdown_frame, text="Choose Receiver", command=self.open_receiver_popup)
        self.choose_receiver_button.pack(pady=5, padx = 5, side = "left")

        self.selected_receiver_id = None  # store selected receiver
        self.selected_receiver_name = ""  # optional, for display

        # Create a frame to hold the buttons side by side
        self.button_frame = ctk.CTkFrame(root, fg_color="transparent")
        self.button_frame.pack(pady=10)

        self.add_button = ctk.CTkButton(self.button_frame, text="Add Task", command=self.add_task)
        self.add_button.pack(side="left", pady=5, padx = 5)  # Use side="left" and padx

        self.delete_tasks_button = ctk.CTkButton(self.button_frame, text="Delete Tasks", command=self.delete_selected_tasks, fg_color="gray", state="disabled")
        self.delete_tasks_button.pack(side="left", pady=5, padx = 5)  # Use side="left" and padx

        self.task_list = ctk.CTkScrollableFrame(root)
        self.task_list.pack(pady=10, fill="both", expand=True)

        self.logout_button = ctk.CTkButton(root, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

        self.load_tasks()

        self.root.bind('<Return>', lambda event=None: self.add_task()) #bind enter to add task

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.root.destroy()
        sys.exit(0)

    def add_task(self):
        """Adds a new task assigned to the selected receiver."""
        task = self.task_entry.get()
        description = self.description_entry.get()
        due_date = self.due_date_entry.get()
        priority = self.priority_menu.get()

        if not task:
            messagebox.showerror("Input Error", "Task name cannot be empty.")
            return

        # Ensure a receiver is selected
        if not self.selected_receiver_id:
            messagebox.showerror("Selection Error", "Please select a receiver before adding the task.")
            return

        try:
            conn = sqlite3.connect("todo_app.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tasks (user_id, assigner_id, task, description, due_date, priority, completed, checked)
                VALUES (?, ?, ?, ?, ?, ?, 0, 0)
            """, (self.selected_receiver_id, self.user_id, task, description, due_date, priority))
            conn.commit()
            conn.close()

            messagebox.showinfo("Success", f"Task assigned to {self.selected_receiver}!")
            self.task_entry.delete(0, "end")
            self.description_entry.delete(0, "end")
            self.due_date_entry.delete(0, "end")
            self.selected_receiver = None
            self.selected_receiver_id = None
            self.load_tasks()  # Refresh task list
        except Exception as e:
            messagebox.showerror("Database Error", f"Error adding task: {e}")


    def load_tasks(self):
        """Loads tasks from the database and displays them in the UI (assigned by current user)."""
        for widget in self.task_list.winfo_children():
            widget.destroy()

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT tasks.id, tasks.task, tasks.description, tasks.due_date,
                tasks.priority, tasks.completed, tasks.checked,
                users.username
            FROM tasks
            JOIN users ON tasks.user_id = users.id
            WHERE tasks.assigner_id = ?
        """, (self.user_id,))
        tasks = cursor.fetchall()
        conn.close()

        self.task_checkboxes = {}

        for task_id, task, description, due_date, priority, completed, checked, receiver_username in tasks:
            task_frame = ctk.CTkFrame(self.task_list)
            task_frame.pack(pady=5, fill="x")

            top_row = ctk.CTkFrame(task_frame, fg_color="transparent")
            top_row.pack(fill="x")

            priority_color = "green"
            if priority == "Medium":
                priority_color = "yellow"
            elif priority == "High":
                priority_color = "red"

            task_label_text = f"{task} (To: {receiver_username})"
            if due_date:
                task_label_text += f" (Due: {due_date})"

            task_label = ctk.CTkLabel(
                top_row, text=task_label_text, anchor="w",
                font=("Helvetica Rounded", 14), wraplength=600, justify="left"
            )
            task_label.pack(side="left", padx=5, fill="x", expand=True)

            if priority != "Choose Priority":
                priority_label = ctk.CTkLabel(
                    task_frame, text=f"(Priority: {priority})",
                    text_color=priority_color, anchor="w",
                    font=("Helvetica Rounded", 14)
                )
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
            checkbox = ctk.CTkCheckBox(
                top_row, text="", variable=checkbox_var,
                command=lambda tid=task_id, checkvar=checkbox_var: self.update_checked(tid, checkvar.get())
            )
            checkbox.pack(side="left", padx=5)
            self.task_checkboxes[task_id] = checkbox_var

            complete_button = ctk.CTkButton(
                task_frame, text="Complete",
                command=lambda tid=task_id, comp=completed, checkvar=checkbox_var: self.toggle_complete(tid, comp, checkvar)
            )
            complete_button.pack(side="right", padx=5)

            if completed:
                complete_button.configure(text="Uncomplete")
                checkbox_var.set(True)
            else:
                checkbox_var.set(False)

            checkbox_var.set(checked)

            if description:
                description_label = ctk.CTkLabel(
                    task_frame, text=f"Description: {description}",
                    anchor="w", font=("Helvetica", 13), wraplength=400, justify="left"
                )
                description_label.pack(anchor="w", padx=5)


    def update_checked(self, task_id, checked_value):
        """Updates the checked status in the database."""
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET checked = ? WHERE id = ?", (int(checked_value), task_id))
        conn.commit()
        conn.close()
        self.update_delete_button_state()

    def update_delete_button_state(self):
        """Updates the state of the delete button based on checkbox selection."""
        checked_tasks = any(var.get() for var in self.task_checkboxes.values())
        if checked_tasks:
            self.delete_tasks_button.configure(state="normal", fg_color="red")
        else:
            self.delete_tasks_button.configure(state="disabled", fg_color="gray")

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

        dialog.bind('<Return>', lambda event=None: self.update_task(task_id, task_entry.get(), description_entry.get(), dialog))

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
        root = App()
        root.mainloop()

    def open_receiver_popup(self):
        """Opens a popup with a list of receiver usernames."""
        # Create a popup window
        popup = ctk.CTkToplevel(self.root)
        popup.title("Select Receiver")
        popup.geometry("300x400")

        # Label for the popup
        label = ctk.CTkLabel(popup, text="Select a Receiver:")
        label.pack(pady=10)

        # Frame for the listbox
        listbox_frame = ctk.CTkFrame(popup)
        listbox_frame.pack(pady=10, fill="both", expand=True)

        # Scrollbar for the listbox
        scrollbar = ctk.CTkScrollbar(listbox_frame)
        scrollbar.pack(side="right", fill="y")

        # Listbox to show receiver usernames
        from tkinter import Listbox, SINGLE
        listbox = Listbox(listbox_frame, selectmode=SINGLE, yscrollcommand=scrollbar.set)
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.configure(command=listbox.yview)

        # Fetch receiver usernames from the database
        try:
            conn = sqlite3.connect("todo_app.db")
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE role = 'receiver'")
            receivers = cursor.fetchall()
            conn.close()

            print("Fetched receivers:", receivers)
            # Populate the listbox with receiver usernames
            if receivers:
                for receiver in receivers:
                    listbox.insert("end", receiver[0])
            else:
                listbox.insert("end", "No receivers found.")
        except Exception as e:
            listbox.insert("end", f"Error loading users: {e}")

        # Function to select the receiver
        def select_receiver():
            selected_index = listbox.curselection()
            if selected_index:
                selected_username = listbox.get(selected_index)

                # Fetch user ID from the database
                try:
                    conn = sqlite3.connect("todo_app.db")
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM users WHERE username = ?", (selected_username,))
                    result = cursor.fetchone()
                    conn.close()

                    if result:
                        self.selected_receiver = selected_username
                        self.selected_receiver_id = result[0]  # Store the ID
                        print(f"Selected receiver: {self.selected_receiver} (ID: {self.selected_receiver_id})")
                except Exception as e:
                    print(f"Error fetching receiver ID: {e}")

                popup.destroy()

        # Select button to confirm the choice
        select_button = ctk.CTkButton(popup, text="Select", command=select_receiver)
        select_button.pack(pady=10)

        # Make the popup modal
        popup.grab_set()
        popup.focus_force()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("400x400")
        self.title("Login/Register App")

        self.login_frame = LoginFrame(self, self.show_register)
        self.register_frame = RegisterFrame(self, self.show_login)

        self.login_frame.pack(fill="both", expand=True)

    def show_register(self):
        self.login_frame.pack_forget()
        self.register_frame.pack(fill="both", expand=True)

    def show_login(self):
        self.register_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def on_logout(self):
        self.deiconify()  # Show login window again
        self.show_login()


class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, show_register_callback):
        super().__init__(master)
        self.show_register_callback = show_register_callback

        ctk.CTkLabel(self, text="Login", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.username_entry.pack(pady=5)

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=5)

        self.error_label = ctk.CTkLabel(self, text="", text_color="red")
        self.error_label.pack()

        ctk.CTkButton(self, text="Login", command=self.login).pack(pady=5)
        ctk.CTkButton(self, text="Register", command=self.show_register_callback).pack(pady=5)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, role FROM users WHERE username=? AND password=?", (username, hashed))
        user = cursor.fetchone()

        if user:
            user_id, role = user 
            self.master.destroy()# close login window

            if role == "assigner":
                main_app = ctk.CTk()
                TodoApp(main_app, user_id) # pass user_id if needed
                main_app.mainloop()
            else:
                main_app = ctk.CTk()
                ReciverApp(main_app, user_id)
                main_app.mainloop()


        else:
            self.error_label.configure(text="Invalid credentials", text_color="red")
        conn.close()


class RegisterFrame(ctk.CTkFrame):
    def __init__(self, master, return_to_login_callback):
        super().__init__(master)
        self.return_to_login_callback = return_to_login_callback

        ctk.CTkLabel(self, text="Register", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.username_entry.pack(pady=5)

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=5)

        self.role_var = ctk.StringVar(value="receiver")
        ctk.CTkLabel(self, text="Select Role").pack()
        ctk.CTkRadioButton(self, text="Assigner", variable=self.role_var, value="assigner").pack()
        ctk.CTkRadioButton(self, text="Receiver", variable=self.role_var, value="receiver").pack()

        self.error_label = ctk.CTkLabel(self, text="", text_color="red")
        self.error_label.pack()

        ctk.CTkButton(self, text="Submit", command=self.register_user).pack(pady=5)
        ctk.CTkButton(self, text="Back to Login", command=self.return_to_login_callback).pack()

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        role = self.role_var.get()

        if not username or not password:
            self.error_label.configure(text="Please fill all fields.")
            return

        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = create_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                           (username, hashed, role))
            conn.commit()
            self.error_label.configure(text="Registration successful!", text_color="green")
            self.after(1000, self.return_to_login_callback)  # Auto-return to login
        except sqlite3.IntegrityError:
            self.error_label.configure(text="Username already exists.", text_color="red")
        finally:
            conn.close()


if __name__ == "__main__":
    app = App()
    app.mainloop()