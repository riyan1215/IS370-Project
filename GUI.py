import hashlib
import socket
import textwrap
import threading
from CTkMessagebox import CTkMessagebox
import customtkinter
from CTkListbox import *
from encryption import encrypt_message,decrypt_message
HEADER = 1024
PORT = 5051
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "/DISCONNECT"
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
class GUI:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    def __init__(self):
        self.thread_running = True
        self.window = None
        self.qr_window = None
        self.map_window = None
        self.frame = None
        self.frameText = None
    def on_exit(self):
        self.thread_running = False  # stop receive thread
        try:
            self.client.send(DISCONNECT_MESSAGE.encode(FORMAT))
        except:
            pass
        try:
            self.client.close()
        except:
            pass
        if self.window:
            self.window.destroy()

    def setup(self):
        if self.window is None:
            self.window = customtkinter.CTk()

        self.window.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.window.geometry('500x500')
        self.window.configure(bg="#252424")
        self.window.title("Chat Application")
        self.frame = customtkinter.CTkFrame(self.window, fg_color='transparent')
        self.frameText = customtkinter.CTkFrame(self.window, fg_color='transparent')


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
        status=self.client.recv(HEADER).decode(FORMAT)
        if status == "200":
            self.client.send(hashlib.sha256(password.encode()).hexdigest().encode(FORMAT))
            status=self.client.recv(HEADER).decode(FORMAT)
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

    def on_user_select(self, selected):
        self.selected_user = selected

    def send_message(self):
        og_message = self.my_msg.get().strip()
        if og_message:
            send_message=""
            if self.category.get()!="All":
                send_message=self.category.get()+" "+og_message
            elif self.category.get() == 'All':
                send_message="!"+" "+og_message
            encrypted_msg = encrypt_message(send_message)
            self.client.send(encrypted_msg.encode(FORMAT))
            if self.category.get()[0]=="@":
                self.msg_list.insert(customtkinter.END, "You:"+ textwrap.fill(og_message,45))
            elif self.category.get()[0]=="#":
                category = self.category.get()
                clean_category = category.removeprefix("'").removesuffix("'")
                wrapped_message = textwrap.fill(og_message, 45)
                self.msg_list.insert(customtkinter.END, f"{clean_category} You: {wrapped_message}")
                self.my_msg.set("")
            try:
                self.msg_list._parent_canvas.yview_moveto(1.0)
            except Exception as e:
                print("Scroll failed (likely on exit):", e)

    def receive(self):
        while self.thread_running:
            try:
                message = self.client.recv(HEADER).decode(FORMAT)
                message = decrypt_message(message)
                if not self.window or not self.window.winfo_exists():
                    break
                if not hasattr(self, "msg_list") or not self.msg_list.winfo_exists():
                    break

                if message.startswith("USER_LIST:"):
                    online_users = message[len("USER_LIST:"):]
                    self.update_user_list(online_users)
                else:
                    self.msg_list.insert(customtkinter.END, f"{message}")
                    try:
                        if hasattr(self.msg_list, "_parent_canvas"):
                            self.msg_list._parent_canvas.yview_moveto(1.0)
                    except Exception as e:
                        print("Scroll error:", e)
            except Exception as e:
                if self.thread_running:  # only show error if it's unexpected
                    print(f"An error occurred: {e}")
                break

    def update_user_list(self, online_users):
        users = online_users.split("\n")
        users.remove("@"+self.username)
        updated_users = ["All"]+[user.strip() for user in users if user.strip()]
        current_user=self.category.get()
        self.online_users = updated_users
        self.category.configure(values=self.online_users)
        self.category.set(self.online_users[0])
        if current_user in self.online_users:
            self.category.set(current_user)
    def refresh_user_list(self):
        message = "/list"
        if message and self.thread_running:
            message=encrypt_message(message)
            self.client.send(message.encode(FORMAT))
        self.window.after(5000, self.refresh_user_list)
if __name__ == "__main__":
    app = Login()
    app.window.mainloop()