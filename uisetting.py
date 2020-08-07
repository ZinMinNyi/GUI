from tkinter import *
from tkinter import ttk

root = Tk()
root.title("Whisper")
root.geometry("1600x800+0+0")
bg = "#333333"
wbg = "white" 
color = "#FFA500"

def click_1():
    a = radio_button.get()
    if a == 1:
        root.config(bg = wbg)

    elif a == 2:
        root.config(bg = bg)

setFrame = Frame(root, bg = bg, bd = 0, width = 800, height = 800, relief = "groove")
setFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 3)
setFrame.pack(anchor = "center", pady = 100)

setLabel = Label(setFrame, text = "Setting", font = ('times',24,'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)
setLabel.grid(row = 0, column = 1,columnspan=3)

modLabel = Label(setFrame, text = "Mode", font = ('times',14,'bold'), bg = bg, fg = color)
modLabel.grid(row = 1, column =1)

radio_button = IntVar()

rb1 = ttk.Radiobutton(setFrame, text = "Light Mode", variable = radio_button, value = 1, command = click_1)
rb1.grid(row = 1, column = 2,sticky="e")

rb2 = ttk.Radiobutton(setFrame, text = "Dark Mode", variable = radio_button, value = 2, command = click_1, style = "Wild.TRadiobutton")
sty = ttk.Style()
sty.configure("Wild.TRadiobutton", background = bg, foreground = wbg)
rb2.grid( row = 1, column = 3,sticky="w")

root.mainloop()