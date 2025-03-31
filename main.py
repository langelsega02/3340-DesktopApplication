from customtkinter import*

counter = 0
def add_todo():
    if(len(entry.get()) == 0):
        return
    
    global counter
    counter += 1

    todo = entry.get()
    checkbox = CTkCheckBox(scroll_frame, text= f"Task {counter}: {todo}")
    checkbox.pack()

    entry.delete(0,END)



root = CTk()
root.title("Main Window")
root.geometry("750x450")

dropdown_name = StringVar()
dropdown_name.set("Hello")

options_list = [
    "Option 1",
    "Option 2",
    "Option 3",
    "Option 4"
]

new_frame = CTkFrame(root)
new_frame_dropdown = CTkOptionMenu(new_frame ,width=183, variable=dropdown_name ,dynamic_resizing=True, values= options_list, anchor="w").pack()
new_frame.pack(fill="y" ,side = "left")

title_label = CTkLabel(root, text="Daily Tasks", font=CTkFont(size=30, weight="bold", family="Comic Sans"))
title_label.pack(padx = 10, pady=(40,20))

scroll_frame = CTkScrollableFrame(root, width=500, height=200)
scroll_frame.pack()

entry = CTkEntry(scroll_frame, placeholder_text="Text")
entry.pack(fill = "x")


add_button = CTkButton(root, text="Add", width=500, command=add_todo)
entry.bind("<Return>", lambda event: add_button.invoke())
add_button.pack(pady=20)



root.mainloop()