import hashlib
import socket
import textwrap
import threading
from CTkMessagebox import CTkMessagebox
import customtkinter
from CTkListbox import *
HEADER = 256
PORT = 5051
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "/DISCONNECT"
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
class GUI:
    def __init__(self):
        self.window = None
        self.qr_window = None
        self.map_window = None
        self.frame = None
        self.frameText = None
    def on_exit(self):
        try:
            self.client.send(DISCONNECT_MESSAGE.encode(FORMAT))
        except:
            pass
        self.client.close()
        self.window.destroy()

    def setup(self):
        if self.window is None:
            self.window = customtkinter.CTk()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(ADDR)

        self.window.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.window.geometry('500x500')
        self.window.configure(bg="#252424")
        self.window.title("Chat Application")
        self.frame = customtkinter.CTkFrame(self.window, fg_color='transparent')
        self.frameText = customtkinter.CTkFrame(self.window, fg_color='transparent')
    def destroy(self):
        if self.window is not None:
            self.window.destroy()


class Login(GUI):
    def __init__(self):
        super().__init__()
        self.setup()
        self.login()

    def login(self):
        self.frame.place(x=180, y=280)
        self.frameText.place(x=180, y=200)

        id_entry = customtkinter.CTkEntry(master=self.frameText, placeholder_text='ID')
        password_entry = customtkinter.CTkEntry(master=self.frameText, placeholder_text='Password', show='*')
        id_entry.pack(pady=(0, 10))
        password_entry.pack()

        customtkinter.CTkButton(self.frame, text="Login", width=40,
                                command=lambda: self.handle_login(id_entry.get(), password_entry.get())).pack(side="left", padx=(40, 10))


    def handle_login(self, user_id, password):
        self.client.send(user_id.encode(FORMAT))
        status=self.client.recv(256).decode(FORMAT)
        if status == "200":
            self.client.send(hashlib.sha256(password.encode()).hexdigest().encode(FORMAT))
            status=self.client.recv(1024).decode(FORMAT)
            if status == "200":
                    self.frame.place_forget()
                    self.frameText.place_forget()
                    Chat(self.window, user_id,self.client)
            else:
                CTkMessagebox(title="Error", message="Password Incorrect!!!", icon="cancel")
        else:
            CTkMessagebox(title="Error", message="Username Incorrect!!!", icon="cancel")

class Chat(GUI):
    def __init__(self,existing_window,username,client):
        super().__init__()
        self.window = existing_window
        self.setup()
        self.username = username

        self.online_users = []
        self.msg_list = None
        self.receive_thread = None
        self.send_thread = None
        self.my_msg = customtkinter.StringVar()
        self.chat()
    def chat(self):
        self.frame.place(x=170, y=250)
        self.frameText.place(x=25, y=380)
        self.msg_list =CTkListbox(self.frame, height=350,width=400)
        self.msg_list.pack(side=customtkinter.LEFT, fill=customtkinter.BOTH)
        self.category = customtkinter.CTkOptionMenu(master=self.frameText, values=self.online_users, width=30,corner_radius=3)
        self.category.pack(side=customtkinter.LEFT, fill=customtkinter.X)
        entry = customtkinter.CTkEntry(master=self.frameText, textvariable=self.my_msg, width=300, placeholder_text="Type a message")
        entry.pack(side=customtkinter.LEFT, padx=(10, 10), pady=(10, 10))
        send_button = customtkinter.CTkButton(master=self.frameText, text="Send", width=60, command=self.send_message,corner_radius=3)
        send_button.pack(side=customtkinter.LEFT, pady=(10, 10))
        self.receive_thread = threading.Thread(target=self.receive, daemon=True)
        self.receive_thread.start()
        self.refresh_user_list()
        self.frame.pack(pady=(0, 10))
        self.window.mainloop()

    def on_user_select(self, selected):
        self.selected_user = selected

    def send_message(self):
        og_message = self.my_msg.get().strip()
        if og_message:
            send_message=""
            if self.category.get()!="All":
                send_message="@"+self.category.get()+" "+og_message
            elif self.category.get() == 'All':
                send_message="!"+" "+og_message
            self.client.send(send_message.encode(FORMAT))
            if self.category.get() != "All":
                self.msg_list.insert(customtkinter.END, "You:"+ textwrap.fill(og_message,45))
            self.my_msg.set("")
            self.msg_list._parent_canvas.yview_moveto(1.0)


    def receive(self):
        while True:
            try:
                message = self.client.recv(1024).decode(FORMAT)

                if message.startswith("USER_LIST:"):
                    online_users = message[len("USER_LIST:"):]
                    self.update_user_list(online_users)
                else:
                    self.msg_list.insert(customtkinter.END, f"{message}")
                    self.msg_list._parent_canvas.yview_moveto(1.0)
            except Exception as e:
                print(f"An error occurred: {e}")
                self.client.close()
                break
    def update_user_list(self, online_users):
        users = online_users.split("\n")
        users[0]="All"
        current_user=self.category.get()
        self.online_users = users
        self.category.configure(values=self.online_users)
        self.category.set(self.online_users[0])
        if current_user in self.online_users:
            self.category.set(current_user)
    def refresh_user_list(self):
        message = "/list"
        if message:
            self.client.send(message.encode(FORMAT))
        self.window.after(5000, self.refresh_user_list)
if __name__ == "__main__":
   # app = Chat(customtkinter.CTk(),"riyan")
    app = Login()
    app.window.mainloop()