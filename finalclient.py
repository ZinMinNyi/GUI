from tkinter import *
from tkinter import ttk


# Client Code
#-----------------------------------------------------------------------------------------
import hashlib
import base64
import json
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Cryptodome.Cipher import AES
from Cryptodome import Random

# For AES Encryptiion
BLOCK_SIZE = 16
pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), 'utf-8')
unpad = lambda s: s[0:-ord(s[-1:])]
# We use the symmetric Encryption So this password have to be the same in both client and server
password = "852020"
homeAccess = False

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
 
def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))
#bytes.decode(decrypt(s.recv(1024), password))

# For Hashing  SHA-1
def myHash(ps):
    hashPassword = hashlib.sha1(ps.encode("utf-8"))
    encrypt = hashPassword.hexdigest()
    return encrypt

# Receiver
def receive():
    while True:
        try:
            msg = bytes.decode(decrypt(client.recv(bufsiz), password))
            msg = json.loads(msg)

            # Signup error replay
            if msg["to"] == "valid":
                print(msg["msg"])

            # Login error reply
            elif msg["to"] == "loginReply":
                homeAccess = bool(msg["access"])
                print(msg["msg"])

            # Login Access
            elif msg["to"] == "loginAccessReply":
                homeAccess = bool(msg["access"])
                accessGranted(access = homeAccess)
                print(homeAccess)

            # Recieve msg
            elif msg["to"] == superuser:
                print(msg['msg'])
                
            # Resiver Going Offline
            elif msg["to"] == "offline":
                print(msg["msg"])
            elif msg["to"] == "aiReply":
                print(msg["msg"])

        except OSError:
            break

# sender
def send(event = None, data = ""):
    client.send(encrypt(data, password))

def sentMsg(msg):
    smsg={'to':'//helpCenter','msg':msg,"from":superuser}
    smsg = json.dumps(smsg)
    send(data = smsg)

# Signup Password validation
def signupAccount(username, ps, reps, email):
    if username and ps and reps and email :
        if "/" not in username:
            if "@" in email:
                if len(ps) >= 8 :
                    if ps == reps :
                        newPassword = myHash(ps)
                        data = {"to":"//signup", "username":username, "ps":newPassword, "email":email}
                        send(data = json.dumps(data))
                
# Try Login Access 
def loginAccount(username, ps):
    global superuser
    superuser = username
    data = {"to":"//login", "username":username, "ps":myHash(ps)}
    send(data = json.dumps(data))

# Access Granted
def accessGranted(access = False):
    if access :
        changeFrame(lf, homeFrame)

# Enter server IP
host = input("Enter Host IP : ")
port = 33000
bufsiz = 1024
addr = (host, port)

# Create socket and Connect to  IP and port
client = socket(AF_INET, SOCK_STREAM)
client.connect(addr)

# Create a thread for recieve 
receiveThread = Thread(target = receive)
receiveThread.start()
#-----------------------------------------------------------------------------------------

root = Tk()
root.title("Whisper")
# width = root.winfo_screenwidth()
# height = root.winfo_screenheight()
# root.geometry(f"{width}x{height}+0+0")
root.geometry("1600x800+0+0")

fg = "#ffffff"
bg = "#333333"
wbg = "white"
color = "#FFA500"
placeholderFg = "light gray"
font = ("book antiqua", 11, 'bold')

# setting Bg Color
root.config(background = bg)

# For close Button
def onClosing(event = None):
    data = {"to":"//clientDisconnect","con":1}
    send(data = json.dumps(data))
    client.close()
    root.quit()
root.protocol("WM_DELETE_WINDOW", onClosing)

def changeFrame(old, new):
    old.destroy()
    new()

def loginFrame():
    global lf

    # Login frame create
    lf = Frame(root, bg = bg, bd = 0, width = 800, height = 800, relief = "solid")
    lf.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)

    # Title
    title = Label(lf, text = 'Whisper', font = ('times', 26, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    # Entry field
    username = Entry(lf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    username.insert(0, "Username  ")
    placeHolder(username, "Username  ")
    
    password = Entry(lf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    password.insert(0, "Password  ")
    placeHolder(password, "Password  ", "♫")

    # Button
    loginButton = Button(lf, font = ("book antiqua", 13, 'bold'), text = "Login", relief = "flat", padx = 22, bg = bg, fg = color, command = lambda username = username, ps = password : loginAccount(username.get(), ps.get()))
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
    sf.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)

    # title
    title = Label(sf, text = 'Signup ', font = ('times', 26, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    # Entry field
    username = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    username.insert(0, "Username  ")
    placeHolder(username, "Username  ")
   
    password = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    password.insert(0, "Password  ")
    placeHolder(password, "Password  ", "♫")
    
    rePassword = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    rePassword.insert(0, "Comfirm Password  ")
    placeHolder(rePassword, "Comfirm Password  ", "♫")
    
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
    rePassword.grid(row = 3, column = 0, columnspan = 4, ipady = 7, ipadx = 30)
    email.grid(row = 4, column = 0, columnspan = 4, pady = 30, ipady = 7, ipadx = 30)
    signupButton.grid(row = 5, column = 1, columnspan = 2)
    backButton.grid(row = 6, column = 1, columnspan = 2, pady = 30)
    # Spadlabel.grid(row = 7, column = 1, pady = 20)

    # Adding current frame to root
    sf.pack(anchor = "center", pady = 100)

def homeFrame():
    navigationFrame()
    chatFrame()
   
def navigationFrame():
    global navFrame
    global user_list

    # Navigation Frame
    navFrame= Frame(root, bg = bg, bd = 0, width = 300, height = 800, relief = "solid")
    navFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)

    # Scrollbar
    scrollBar = Scrollbar(navFrame, bg = 'red', troughcolor = "red")
    searchBar=Entry(navFrame,font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    searchBar.insert(0, "Search Users")
    placeHolder(searchBar, "Search Users")
    user_list = Listbox(navFrame, yscrollcommand = scrollBar.set, bg = bg, height = 40, width = 36)

    for line in range(100):
        user_list.insert(END, "Number" + str(line))

    settingButton = Button(navFrame, text = "Setting", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 22, bg = bg, fg = color)
    settingButton.pack(side = BOTTOM, fill = BOTH)

    scrollBar.pack(side = RIGHT, fill = Y)
    scrollBar.config(command = user_list.yview)
    searchBar.pack(side = TOP, ipady = 7)
    user_list.pack(side = LEFT, fill = BOTH, pady = 2)
    navFrame.pack(side = LEFT, padx = 10)

def chatFrame():
    global chatFrame
    chatFrame = Frame(root, bg = bg, bd = 0, width = 1000, height = 710, relief = "flat")
    chatFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 1)

    msgShowFrame = Frame(chatFrame, bg = bg, width = 1000, height = 400, relief = "flat")
    msgShowFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 1)
    
    messages_frame = Frame(msgShowFrame)
    my_msg = StringVar()  # For the messages to be sent.
    my_msg.set("Type Your Messages Here...")
    
    scrollbar = Scrollbar(messages_frame)  # To navigate through past messages.
    # Following will contain the messages.
    msg_list = Listbox(messages_frame, height = 39, width = 200, yscrollcommand = scrollbar.set, bg = bg)
    scrollbar.pack(side = RIGHT, fill = Y)
    msg_list.pack(side = LEFT, fill = BOTH)
    msg_list.pack(side = RIGHT, fill = BOTH)
    messages_frame.pack()

    sentMsgFrame = Frame(chatFrame, bg = bg, width = 1000, height = 300)
    sentMsgEntry = Entry(sentMsgFrame, font = ("book antiqua", 13, 'bold'), textvariable = my_msg, bg = wbg, fg = bg, width = 110, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth =2)

    sentMsgButton = Button(sentMsgFrame, text = "Sent", font = ("book antiqua", 13, 'bold'), relief = "flat", bg = bg, fg = color, width = 90, command = lambda msg = sentMsgEntry:sentMsg(msg.get()))

    msgShowFrame.pack(side = TOP)
    sentMsgFrame.pack(side = BOTTOM)
    sentMsgEntry.pack(side = LEFT, ipady = 30)
    sentMsgButton.pack(side = LEFT, ipady = 10, fill = BOTH)
    chatFrame.pack(side = LEFT, padx = 30)

def settingFrame():
    setFrame = Frame(root, bg = bg, bd = 0, width = 300, height = 500, relief = "solid")
    setFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)
    setFrame.pack(side=LEFT, padx = 30)

    profileLabel = Label(setFrame, text = "Profile", font = ('times', 24, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)
    userLabel = Label(setFrame, text = "         Username : ", font = ("book antiqua", 14, 'bold'), bg = bg, fg = color)
    emailLabel =  Label(setFrame, text = "  Email : ", font = ("book antiqua", 14, 'bold'), bg = bg, fg = color)
    setLabel = Label(setFrame, text = "Setting", font = ('times', 24, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)
    modLabel = Label(setFrame, text = "Mode :", font = ("book antiqua", 14, 'bold'), bg = bg, fg = color)
    themeLabel = Label(setFrame, text = "   Themes :", font = ("book antiqua", 14, 'bold'), bg = bg, fg = color)
    changePwdLabel = Label(setFrame, text = "Change Password", font = ('times', 24, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    profileLabel.grid(row = 0, column = 1, columnspan = 4)
    userLabel.grid(row = 1, column = 1, pady = 15)
    emailLabel.grid(row = 2, column = 1)
    setLabel.grid(row = 3, column = 1, columnspan = 4)
    modLabel.grid(row = 4, column = 1, pady = 15)
    themeLabel.grid(row = 5, column = 1)
    changePwdLabel.grid(row = 6, column = 1, columnspan = 4, pady = 15)

    # radio button for mode
    def click_1():
        a = radio_button.get()
        if a == 1:
            root.config(bg = wbg)
            setFrame.config(bg = wbg)
            setLabel.config(bg = wbg)
            profileLabel.config(bg = wbg)
            userLabel.config(bg = wbg)
            emailLabel.config(bg = wbg)
            modLabel.config(bg = wbg)
            themeLabel.config(bg = wbg)
            changePwdLabel.config(bg = wbg)
            currentPwd.config(bg = wbg)
            newPwd.config(bg = wbg)
            comfirmPwd.config(bg = wbg)
            changePwdButton.config(bg = wbg)
            logoutButton.config(bg = wbg)

        elif a == 2:
            root.config(bg = bg)
            setFrame.config(bg = bg)
            setLabel.config(bg = bg)
            profileLabel.config(bg = bg)
            userLabel.config(bg = bg)
            emailLabel.config(bg = bg)
            modLabel.config(bg = bg)
            themeLabel.config(bg = bg)
            changePwdLabel.config(bg = bg)
            currentPwd.config(bg = bg)
            newPwd.config(bg = bg)
            comfirmPwd.config(bg = bg)
            changePwdButton.config(bg = bg)
            logoutButton.config(bg = bg)

    radio_button = IntVar()
    rb1 = ttk.Radiobutton(setFrame, text = "Light Mode", variable = radio_button, value = 1, command = click_1)
    rb2 = ttk.Radiobutton(setFrame, text = "Dark Mode", variable = radio_button, value = 2, command = click_1, style = "Wild.TRadiobutton")
    sty = ttk.Style()
    sty.configure("Wild.TRadiobutton", background = bg, foreground = wbg)
    rb1.grid(row = 4, column = 2, columnspan = 1, sticky = "e")
    rb2.grid(row = 4, column = 3, columnspan = 1, sticky = "w")

    # combo box for theme
    def select_item(event):
        a = theme.get()
        if a == "Theme-1":
            root.config(background = "light blue")

        elif a == "Theme-2":
            root.config(background = "gray")

        elif a == "Theme-3":
            root.config(background = "aqua")

    theme = ttk.Combobox(setFrame, values = ("Theme-1", "Theme-2", "Theme-3"), font = font, justify = CENTER, width = 14, height = 40)
    theme.grid(row = 5, column = 2, columnspan = 2)
    theme.set("Select Themes")
    theme.bind("<<ComboboxSelected>>", select_item)

    # Change Password Entry
    currentPwd = Entry(setFrame, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    currentPwd.insert(0, "Current Password")
    placeHolder(currentPwd, "Current Password")
   
    newPwd = Entry(setFrame, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    newPwd.insert(0, "New Password")
    placeHolder(newPwd, "New Password", "♫")
    
    comfirmPwd = Entry(setFrame, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth = 3)
    comfirmPwd.insert(0, "Comfirm Password")
    placeHolder(comfirmPwd, "Comfirm Password", "♫")

    currentPwd.grid(row = 7, column = 0, columnspan = 4, ipady = 7, ipadx = 30)
    newPwd.grid(row = 8, column = 0, columnspan = 4, pady = 30, ipady = 7, ipadx = 30)
    comfirmPwd.grid(row = 9, column = 0, columnspan = 4, ipady = 7, ipadx = 30)

    # Button
    changePwdButton = Button(setFrame, text = "Change", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 10, bg = bg, fg = color)
    logoutButton = Button(setFrame, text = "Logout", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 24, bg = bg, fg = color)
    backButton_2 = Button(setFrame, text = "Back", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 24, bg = bg, fg = color)

    changePwdButton.grid(row = 9, column = 3, sticky = "e")
    backButton_2.grid(row = 10, column = 1, sticky = "e")
    logoutButton.grid(row = 10, column = 2, pady = 40)

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

loginFrame()
root.mainloop()
