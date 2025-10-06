from tkinter import ttk

def create_tooltip(widget, text):
    """Creates a tooltip for a given Tkinter widget.

    This function attaches a tooltip to a widget, which appears when the mouse
    hovers over it. The tooltip is a simple label with a yellow background.

    Args:
        widget: The Tkinter widget to which the tooltip will be attached.
        text (str): The text to be displayed in the tooltip.
    """
    tool_tip = ttk.Label(widget, text=text, background="yellow", relief="solid", borderwidth=1, wraplength=150)
    def enter(event):
        tool_tip.place(x=event.x + widget.winfo_x(), y=event.y + widget.winfo_y() + 20)
    def leave(event):
        tool_tip.place_forget()
    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)
