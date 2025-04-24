import hashlib
import socket
import sys
import threading
import time
from datetime import datetime
from io import BytesIO

import customtkinter
from CTkMessagebox import CTkMessagebox
from PIL import Image

from utility.encryption import encrypt_message, decrypt_message
#Config
HEADER = 1024
PORT = 5051
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "/DISCONNECT"
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
#Colors
RED_COLOR = "\033[91m"


class GUI:
    def __init__(self, client=None):
        if client is None:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.client.connect(ADDR)
            except socket.error as msg:
                print(
                    "Connection error: %s" % msg + RED_COLOR + "\nMake sure that the server is running and the port is open, and then try again")
                hello = CTkMessagebox(title="Connection Error",
                                      message="Make sure that the server is running and the port is open, and then try again",
                                      icon="cancel")
                if hello.get() == "OK":
                    sys.exit()
        else:
            self.client = client
        self.thread_running = True
        self.window = None
        self.frame = None
        self.frameText = None
        self.frameText2 = None

    def on_exit(self):
        self.thread_running = False
        try:
            self.client.sendall(encrypt_message(DISCONNECT_MESSAGE).encode(FORMAT))
        except  (OSError, Exception) as e:
            print("Error disconnecting: %s", e)
        try:
            self.client.close()
        except (OSError, Exception) as e:
            print("Error closing socket: %s", e)
        if self.window:
            self.window.destroy()

    def setup(self):
        if self.window is None:
            self.window = customtkinter.CTk()
        self.window.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.window.geometry('500x500')
        self.window.resizable(width=False, height=False)
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
                                command=lambda: self.handle_login(id_entry.get(), password_entry.get())).pack(
            side="left", padx=(40, 10))

    def handle_login(self, user_id, password):
        self.client.sendall(user_id.encode(FORMAT))
        status = self.client.recv(HEADER).decode(FORMAT)
        if status == "200":
            self.client.sendall(hashlib.sha256(password.encode()).hexdigest().encode(FORMAT))
            status = self.client.recv(HEADER).decode(FORMAT)
            if status == "200":
                self.frame.place_forget()
                self.frameText.place_forget()
                Chat(self.window, user_id, self.client)
            elif status == "409":
                CTkMessagebox(title="Error", message="Already Logged In", icon="cancel")
            else:
                CTkMessagebox(title="Error", message="Password Incorrect!!!", icon="cancel")
        else:
            CTkMessagebox(title="Error", message="Username Incorrect!!!", icon="cancel")


class Chat(GUI):
    def __init__(self, existing_window, username, client):
        super().__init__(client)
        self.category = None
        self.window = existing_window
        self.setup()
        self.username = username
        self.online_users = []
        self.msg_list = None
        self.receive_thread = None
        self.my_msg = customtkinter.StringVar()
        self.chat()
        self.msg_list_lock = threading.Lock()

    def chat(self):
        self.frame.place(x=170, y=250)
        self.frameText.place(x=25, y=380)
        self.frameText2.place(x=390, y=430)
        self.msg_list = customtkinter.CTkScrollableFrame(self.frame, width=400, height=350)
        self.msg_list.pack(side=customtkinter.LEFT, fill=customtkinter.BOTH)
        self.category = customtkinter.CTkOptionMenu(master=self.frameText, values=self.online_users, width=30,
                                                    corner_radius=3,command=self.on_category_change,)
        self.category.pack(side=customtkinter.LEFT, fill=customtkinter.X)
        self.window.after(100, lambda: self.on_category_change(self.category.get())) #for the first selection

        entry = customtkinter.CTkEntry(master=self.frameText, textvariable=self.my_msg, width=300,
                                       placeholder_text="Type a message")
        entry.pack(side=customtkinter.LEFT, padx=(10, 10), pady=(10, 10))
        send_button = customtkinter.CTkButton(master=self.frameText, text="Send", width=60, command=self.send_message,
                                              corner_radius=3)
        send_button.pack(side=customtkinter.LEFT, pady=(10, 10))
        select_image = customtkinter.CTkButton(self.frameText2, text="Send Image", width=40,
                                               command=lambda: self.send_image(customtkinter.filedialog.askopenfilename(
                                                   filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])), corner_radius=3)
        select_image.pack(side=customtkinter.LEFT, fill=customtkinter.X)
        self.receive_thread = threading.Thread(target=self.receive, daemon=True)
        self.receive_thread.start()
        self.frame.pack(pady=(0, 10))

    def send_message(self):
        og_message = self.my_msg.get().strip()
        if og_message:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean_category = self.category.get().removeprefix("'").removesuffix("'")
            send_message = ""
            if self.category.get() != "All":
                send_message = self.category.get() + " " + og_message
            elif self.category.get() == 'All':  # Broadcast
                send_message = "!" + " " + og_message
                chat = f"[{timestamp}] {self.username} ➔ ALL :: {og_message}"
                with self.msg_list_lock:
                    msg_label = customtkinter.CTkLabel(self.msg_list, text=chat, anchor="w", justify="left",
                                                   wraplength=300)
                    msg_label.pack(fill="x", padx=5, pady=2, anchor="w")

            encrypted_msg = encrypt_message(send_message)
            self.client.sendall(encrypted_msg.encode(FORMAT))
            if self.category.get()[0] == "@" or self.category.get()[0]=="#":  # Unicast and Multicast
                chat = f"[{timestamp}] {self.username} ➔ {'GROUP' if self.category.get()[0]=='#' else ''} {clean_category[1:]} :: {og_message}"
                with self.msg_list_lock:
                    msg_label = customtkinter.CTkLabel(self.msg_list, text=chat, anchor="w", justify="left",
                                                   wraplength=300)
                    msg_label.pack(fill="x", padx=5, pady=2, anchor="w")

            self.my_msg.set("")
            self.msg_list.update_idletasks()
            self.msg_list._parent_canvas.yview_moveto(1.0)

    def send_image(self, image):
        try:
            if image:
                with open(image, "rb") as f:
                    image_file = f.read()
                time.sleep(1)
                size_bytes = len(image_file).to_bytes(4, 'big')
                self.client.sendall(encrypt_message(f"/Image {self.category.get()}").encode(FORMAT))
                self.client.sendall(size_bytes)
                for i in range(0, len(image_file), HEADER):
                    self.client.sendall(image_file[i:i + HEADER])
                image_stream = BytesIO(image_file)
                img = customtkinter.CTkImage(dark_image=Image.open(image_stream), size=(100, 100))
                label = customtkinter.CTkLabel(self.msg_list, image=img, text="")
                label.image = img
                label.pack(padx=5, pady=5, anchor="w")
        except Exception as e:
            print("sendImage:", e)

    def receive_image(self):
        try:
            size_bytes = self.client.recv(4)  # receives the size of the image
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
                    self.receive_image()
                else:
                    if message.startswith("/history:"):
                        self.history_receive()
                    elif message.startswith("/history_end") or message.startswith("/history_error"):
                        pass
                    else:
                        with self.msg_list_lock:
                            msg_label = customtkinter.CTkLabel(self.msg_list, text=message, 
                                                              anchor="w", justify="left",
                                                              wraplength=300)
                            msg_label.pack(fill="x", padx=5, pady=2, anchor="w")
                    self.msg_list._parent_canvas.yview_moveto(1.0)
            except Exception as e:
                if self.thread_running:
                    print(f"An error occurred: {e}")
                break

    def update_user_list(self, online_users):
        users = online_users.split("\n")
        users.remove("@" + self.username)  # so that the user doesn't send it to himself
        updated_users = ["All"] + [user.strip() for user in users if user.strip()]
        current_user = self.category.get()
        self.online_users = updated_users
        self.category.configure(values=self.online_users)
        self.category.set(self.online_users[0])
        if current_user in self.online_users:
            self.category.set(current_user)

    def request_history(self, history_type, identifier=None):
        if history_type == "broadcast":
            history_cmd = "/get_history broadcast"
        elif history_type in ("unicast", "multicast") and identifier:
            history_cmd = f"/get_history {history_type} {identifier}"
        else:
            return  # Invalid usage
        encrypted = encrypt_message(history_cmd)
        self.client.sendall(encrypted.encode(FORMAT))

    def on_category_change(self, selected):
        # Clear the current chat display
        with self.msg_list_lock:
            for widget in self.msg_list.winfo_children():
                widget.destroy()
        self.msg_list._parent_canvas.yview_moveto(0.0)

        if selected == "All":
            history_type = "broadcast"
            identifier = None
        elif selected.startswith("@"):
            history_type = "unicast"
            identifier = selected[1:]
        elif selected.startswith("#"):
            history_type = "multicast"
            identifier = selected[1:]

        self.request_history(history_type, identifier)

    def history_receive(self):
        try:
            bytes_chunks = int.from_bytes(self.client.recv(4), 'big')
            received = b""
            while len(received) < bytes_chunks:
                chunk = self.client.recv(min(bytes_chunks - len(received), HEADER))
                received += chunk

            _ = self.client.recv(HEADER)

            try:
                history = decrypt_message(received.decode(FORMAT))
            except Exception as e:
                print(f"Error decrypting: {e}")
                return

            for line in history.splitlines():
                if " :: [Image]" in line:
                    try:
                        path_part = line.split(" :: [Image]")[1]
                        image_path = path_part.lstrip()
                        self.client.sendall(encrypt_message("/img_log " + image_path).encode(FORMAT))
                        self.receive_image()
                    except Exception as e:
                        print(f"Error processing image '{line}': {e}")
                    continue


                with self.msg_list_lock:
                    msg_label = customtkinter.CTkLabel(self.msg_list, text=line, anchor="w", justify="left", wraplength=300)
                    msg_label.pack(fill="x", padx=5, pady=2, anchor="w")

        except Exception as e:
            print(f"Unexpected error: {e}")


if __name__ == "__main__":
    app = Login()
    app.window.mainloop()