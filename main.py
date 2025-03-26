from tkinter import *

#Window Functions
def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")

    
def window_name(window, title_name):
    window.title(title_name)


#Windows
main_window = Tk()
main_window.geometry("420x420")
center_window(main_window)
window_name(main_window, "Main Window")

def popup():
    popup_window = Tk()
    popup_window.geometry("420x420")
    center_window(popup_window)
    window_name(popup_window, "Popup Window")


#Widgets
popup_window_button = Button(main_window, text="Press for Pop-up!", command=popup)
popup_window_button.pack(anchor="center")

mainloop()


