import socket
import threading
from database import check_user,login,group_members,groups
import os
from datetime import datetime
from encryption import encrypt_message, decrypt_message
HEADER = 1024
PORT = 5051
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "/DISCONNECT"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
clients = {} #user-->connection

def log_message(log_type, sender, receiver_or_group, message):
    if not os.path.exists("logs"):
        os.makedirs("logs")
        os.makedirs("logs/unicast")
        os.makedirs("logs/multicast")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    if log_type == "unicast":
        List1=[sender,receiver_or_group]
        List1=sorted(List1)
        filename = f"unicast/{List1[0]}_{List1[1]}.txt"
        log_line = f"[{timestamp}] {sender} ➔ {receiver_or_group} :: {message}"
    elif log_type == "broadcast":
        filename = "broadcast.txt"
        log_line = f"[{timestamp}] {sender} ➔ ALL :: {message}"
    elif log_type == "multicast":
        filename = f"multicast/{receiver_or_group}.txt"
        log_line = f"[{timestamp}] {sender} ➔ GROUP [{receiver_or_group}] :: {message}"
    else:
        return

    with open(f"logs/{filename}", "a", encoding="utf-8") as f:
        f.write(log_line + "\n")

def authenticate(conn):
    while True:
        username = conn.recv(HEADER).decode()
        username_check=check_user(username)
        if username_check:
            conn.send(b"200") #correct username
            password = conn.recv(HEADER).decode()
            check_password =login(username,password)
            if check_password:
                conn.send(b"200") #correct password
                clients[username] = conn
                return username
            else:
                conn.send(b"401") #incorrect password
        else:
            conn.send(b"404") #incorrect username

def unicast(oguser, user, msg):
    if user in clients:
        full_msg = f"{oguser}: {msg}"
        clients[user].send(encrypt_message(full_msg).encode(FORMAT))
        log_message("unicast", oguser, user, msg)
    else:
        print("user is not connected")


def broadcast(user, msg2):
    full_msg = f"[BROADCAST] {user}: {msg2}"
    for client in clients:
        clients[client].send(encrypt_message(full_msg).encode(FORMAT))
    log_message("broadcast", user, "ALL", msg2)


def multicast(group, msg2, oguser):
    group_names = group_members(group)
    full_msg = f"#{group} {oguser}: {msg2}"
    for user in group_names:
        if user != oguser and user in clients:
            clients[user].send(encrypt_message(full_msg).encode(FORMAT))
            log_message("multicast", oguser, group, msg2)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    user = authenticate(conn)
    if user:
        connected = True
        try:
            while connected:
                    msg = decrypt_message(conn.recv(HEADER).decode())
                    if msg[0] == "@": #unicast
                        user2, msg2 = msg[1:].split(" ", 1)
                        unicast(user, user2, msg2)
                    elif msg[0] == "!": #broadcast
                        u,msg2 = msg[1:].split(" ", 1)
                        broadcast(user, msg2)
                    elif msg[0] == "#":
                        u,msg2=msg[1:].split(" ", 1)
                        multicast(u, msg2,user)
                    elif msg == "/list":
                        user_list = [f"@{u}" for u in clients.keys()]
                        user_groups = groups(user)
                        group_list = ["#" + g for g in user_groups] if user_groups else []
                        combined = "\n".join(user_list + group_list)
                        encrypted_userlist=encrypt_message(f"USER_LIST:\n{combined}")
                        conn.send(encrypted_userlist.encode(FORMAT))
                    if msg == DISCONNECT_MESSAGE:
                        connected = False
        except Exception as e:
            print(f"[ERROR] Exception with user {user}: {e}")
        finally:
            print(f"[{user}] Disconnected")
            if user in clients:
                del clients[user]
            conn.close()
    else:
        conn.close()
def start():
    server.listen()
    print(f"[Listening] Server is Listening in {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

print("[STARTING] server is starting...")
start()
