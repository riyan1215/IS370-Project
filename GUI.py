import hashlib
import socket
import textwrap
import threading
from CTkMessagebox import CTkMessagebox
from customtkinter import filedialog
import customtkinter
from encryption import encrypt_message, decrypt_message
from PIL import Image
from io import BytesIO
import sys

HEADER = 1024
PORT = 5051
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "/DISCONNECT"
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)

class GUI:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(ADDR)
    except socket.error as msg:
        print("Connection error: %s" % msg)
        sys.exit()
    def __init__(self):
        self.thread_running = True
        self.window = None
        self.frame = None
        self.frameText = None
        self.frameText2 = None
    def on_exit(self):
        self.thread_running = False
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
        self.frameText2 = customtkinter.CTkFrame(self.window, fg_color='transparent')

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
        status = self.client.recv(HEADER).decode(FORMAT)
        if status == "200":
            self.client.send(hashlib.sha256(password.encode()).hexdigest().encode(FORMAT))
            status = self.client.recv(HEADER).decode(FORMAT)
            if status == "200":
                self.frame.place_forget()
                self.frameText.place_forget()
                Chat(self.window, user_id, self.client)
            else:
                CTkMessagebox(title="Error", message="Password Incorrect!!!", icon="cancel")
        else:
            CTkMessagebox(title="Error", message="Username Incorrect!!!", icon="cancel")

class Chat(GUI):
    def __init__(self, existing_window, username, client):
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
        self.frameText2.place(x=380, y=430)
        self.msg_list = customtkinter.CTkScrollableFrame(self.frame, width=400, height=350)
        self.msg_list.pack(side=customtkinter.LEFT, fill=customtkinter.BOTH)
        self.category = customtkinter.CTkOptionMenu(master=self.frameText, values=self.online_users, width=30, corner_radius=3)
        self.category.pack(side=customtkinter.LEFT, fill=customtkinter.X)
        entry = customtkinter.CTkEntry(master=self.frameText, textvariable=self.my_msg, width=300, placeholder_text="Type a message")
        entry.pack(side=customtkinter.LEFT, padx=(10, 10), pady=(10, 10))
        send_button = customtkinter.CTkButton(master=self.frameText, text="Send", width=60, command=self.send_message, corner_radius=3)
        send_button.pack(side=customtkinter.LEFT, pady=(10, 10))
        select_image = customtkinter.CTkButton(self.frameText2, text="Send Image", width=40, command=lambda: self.sendImage(filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])))
        select_image.pack(side=customtkinter.LEFT, fill=customtkinter.X)
        self.receive_thread = threading.Thread(target=self.receive, daemon=True)
        self.receive_thread.start()
        self.refresh_user_list()
        self.frame.pack(pady=(0, 10))
    def send_message(self):
        og_message = self.my_msg.get().strip()
        if og_message:
            send_message = ""
            if self.category.get() != "All":
                send_message = self.category.get() + " " + og_message
            elif self.category.get() == 'All':
                send_message = "!" + " " + og_message
            encrypted_msg = encrypt_message(send_message)
            self.client.send(encrypted_msg.encode(FORMAT))
            if self.category.get()[0]=="@":
                msg_text = "You: " + textwrap.fill(og_message, 45)
                msg_label = customtkinter.CTkLabel(self.msg_list, text=msg_text, anchor="w", justify="left",
                                                   wraplength=300)
                msg_label.pack(fill="x", padx=5, pady=2, anchor="w")
            elif self.category.get()[0]=="#":
                category = self.category.get()
                clean_category = category.removeprefix("'").removesuffix("'")
                wrapped_message = textwrap.fill(og_message, 45)
                group_text = f"{clean_category} You: {wrapped_message}"
                group_label = customtkinter.CTkLabel(self.msg_list, text=group_text, anchor="w", justify="left",
                                                     wraplength=300)
                group_label.pack(fill="x", padx=5, pady=2, anchor="w")

            self.my_msg.set("")
            self.msg_list.update_idletasks()
            self.msg_list._parent_canvas.yview_moveto(1.0)
    def sendImage(self, image):
        try:
            with open(image, "rb") as f:
                image_file = f.read()
            size_bytes = len(image_file).to_bytes(4, 'big')
            self.client.send(encrypt_message(f"/Image {self.category.get()}").encode(FORMAT))
            self.client.send(size_bytes)
            self.client.sendall(image_file)
            image_stream = BytesIO(image_file)
            img = customtkinter.CTkImage(dark_image=Image.open(image_stream), size=(100, 100))
            label = customtkinter.CTkLabel(self.msg_list, image=img, text="")
            label.image = img
            label.pack(padx=5, pady=5, anchor="w")
        except Exception as e:
            print("sendImage:", e)
    def receiveImage(self):
        try:
            size_bytes = self.client.recv(4)
            size = int.from_bytes(size_bytes, 'big')
            received = b""
            while len(received) < size:
                chunk = self.client.recv(min(size - len(received), HEADER))
                if not chunk:
                    break
                received += chunk
            image = Image.open(BytesIO(received))
            img_display = customtkinter.CTkImage(dark_image=image, size=(100, 100))
            label = customtkinter.CTkLabel(self.msg_list, image=img_display, text="")
            label.image = img_display
            label.pack(padx=5, pady=5, anchor="w")
        except Exception as e:
            print("Error receiving image:", e)
    def receive(self):
        while self.thread_running:
            try:
                message = self.client.recv(HEADER).decode(FORMAT)
                message = decrypt_message(message).lstrip()
                if not self.window or not self.window.winfo_exists():
                    break
                if message.startswith("USER_LIST:"):
                    online_users = message[len("USER_LIST:"):]
                    self.update_user_list(online_users)
                elif message.startswith("/Image:"):
                    self.receiveImage()
                else:
                    msg_label = customtkinter.CTkLabel(self.msg_list, text=message, anchor="w", justify="left", wraplength=300)
                    msg_label.pack(fill="x", padx=5, pady=2, anchor="w")
            except Exception as e:
                if self.thread_running:
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
            message = encrypt_message(message)
            self.client.send(message.encode(FORMAT))
        self.window.after(5000, self.refresh_user_list)
if __name__ == "__main__":
    app = Login()
    app.window.mainloop()