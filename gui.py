from tkinter import *
#from client import *

root = Tk()
root.title("Whisper")
root.geometry("1600x800+0+0")

fg = "#ffffff"
bg = "#333333"
color = "#FFA500"
placeholderFg = "light gray"
font = ("book antiqua", 11, 'bold')

# setting Bg Color
root.config(background = bg)

def changeFrame(old, new):
    old.destroy()
    new()

def loginFrame():
    # Login frame create
    lf = Frame(root,bg = bg, bd = 0, width = 800, height = 800, relief = "solid")
    lf.config(highlightcolor = color, highlightbackground = color, highlightthickness = 3)

    # Title
    title = Label(lf, text = 'Whisper', font = ('times', 26, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    # Entry field
    username = Entry(lf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    username.insert(0, "Username  ")
    placeHolder(username, "Username  ")
    
    password = Entry(lf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    password.insert(0, "Password  ")
    placeHolder(password, "Password  ", "♥")

    # Button
    loginButton = Button(lf, font = ("book antiqua", 13, 'bold'), text = "Login", relief = "flat", padx = 22, bg = bg, fg = color, command = lambda username = username, ps=password : loginAccount(username.get(), ps.get()))
    signupButton = Button(lf, font = ("book antiqua", 13, 'bold'), text = "Signup", relief = "flat", padx = 18, bg = bg, fg = color, command = lambda : changeFrame(lf, signupFrame))

    # Padding Bottom
    # Lpadlabel=Label(lf, bg = bg)

    # Adding into current frame
    title.grid(row = 0, column = 1)
    username.grid(row = 1, column = 0, columnspan = 4, pady = 20, ipady = 7, ipadx = 30)
    password.grid(row = 2, column = 0, columnspan = 4, pady = 20, ipady = 7, ipadx = 30)
    loginButton.grid(row = 3, column = 1, columnspan = 2)
    signupButton.grid(row = 4, column = 1, columnspan = 2, pady = 30)
    # Lpadlabel.grid(row = 5, column = 1, pady = 10)

    # Adding current frame to root
    lf.pack(anchor = "center", pady = 100)

def signupFrame():
    # Signup frame create
    sf = Frame(root, bg = bg, bd = 0, width = 800, height = 800, relief = "solid")
    sf.config(highlightcolor = color, highlightbackground = color, highlightthickness = 3)

    # title
    title = Label(sf, text = 'Signup ', font = ('times', 26, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    # Entry field
    username = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    username.insert(0, "Username  ")
    placeHolder(username, "Username  ")
    
   
    password = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    password.insert(0, "Password  ")
    placeHolder(password, "Password  ", "♥")
    
    rePassword = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    rePassword.insert(0, "Comfirm Password  ")
    placeHolder(rePassword, "Comfirm Password  ", "♥")
    
    email = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    email.insert(0, "Email  ")
    placeHolder(email, "Email  ")
    
    # Button
    signupButton = Button(sf, text = "Signup", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 18, bg = bg, fg = color, command = lambda username = username, ps = password, reps = password, email = email : signupAccount(username.get(), ps.get(), reps.get(), email.get()))
    backButton = Button(sf, text = "Back", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 24, bg = bg, fg = color, command = lambda : changeFrame(sf, loginFrame))

    # Padding
    # Spadlabel = Label(sf, bg = bg)

    # Adding into current frame
    title.grid(row = 0, column = 1)
    username.grid(row = 1, column = 0, columnspan = 4, ipady = 7, ipadx = 30)
    password.grid(row = 2, column = 0, columnspan = 4, pady = 30, ipady = 7, ipadx = 30)
    rePassword.grid(row = 3, column = 0, columnspan = 4, ipady = 7,ipadx = 30)
    email.grid(row = 4, column = 0, columnspan = 4, pady = 30, ipady = 7, ipadx = 30)
    signupButton.grid(row = 5, column = 1, columnspan = 2)
    backButton.grid(row = 6, column = 1, columnspan = 2, pady = 30)
    # Spadlabel.grid(row = 7, column = 1, pady = 20)

    # Adding current frame to root
    sf.pack(anchor = "center", pady = 100)


#for Place holder
def placeHolder(ent, plce = "" , s = ""):
    #for placehokder text
    def putPlaceholder(ent):
        ent.config(show = "")
        ent.config(fg = "light gray")
        ent.insert(0, plce)

    #if click the entry
    def focIn(*args):
        if ent.get() == plce:
            ent.delete(0, END)
            ent.config(fg = color)
            ent.config(show = s)
        
    #not click the entry
    def focOut(*args):
        if not ent.get():
            putPlaceholder(ent)
        
    ent.bind("<FocusIn>", focIn)
    ent.bind("<FocusOut>", focOut)
    
# For close Button
def onClosing(event = None):
    #client.close()
    root.quit()

root.protocol("WM_DELETE_WINDOW", onClosing)
loginFrame()
root.mainloop()
