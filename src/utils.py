from tkinter import ttk

def create_tooltip(widget, text):
    tool_tip = ttk.Label(widget, text=text, background="yellow", relief="solid", borderwidth=1, wraplength=150)
    def enter(event):
        tool_tip.place(x=event.x + widget.winfo_x(), y=event.y + widget.winfo_y() + 20)
    def leave(event):
        tool_tip.place_forget()
    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)
