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
    os.makedirs("logs/unicast", exist_ok=True)
    os.makedirs("logs/multicast", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if log_type == "unicast":
        List1 = sorted([sender, receiver_or_group])
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

def image(conn, sender, route):
    try:
        # 1. Receive 4 bytes for size (not encoded/encrypted)
        size_bytes = conn.recv(4)
        size = int.from_bytes(size_bytes, 'big')
        # 2. Receive image data
        received = b""
        while len(received) < size:
            chunk = conn.recv(min(size - len(received), HEADER))
            if not chunk:
                break
            received += chunk
        # Save image
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        os.makedirs("logs/images", exist_ok=True)
        image_path = f"logs/images/{sender}_{timestamp}.jpg"
        with open(image_path, "wb") as f:
            f.write(received)
        # Share notification
        share_message = encrypt_message(f"/Image:").encode(FORMAT)
        if route.startswith("@"):
            target = route[1:]
            if target in clients:
                clients[target].send(share_message)
                clients[target].send(size_bytes)
                clients[target].sendall(received)
                log_message("unicast", sender, target, f"[Image] {image_path}")
        elif route.startswith("#"):
            group = route[1:]
            members = group_members(group)
            for user in members:
                if user != sender and user in clients:
                    clients[user].send(share_message)
                    clients[user].send(size_bytes)
                    clients[user].sendall(received)
            log_message("multicast", sender, group, f"[Image] {image_path}")
        elif route.startswith("All"):
            for user in clients:
                if user != sender:
                    clients[user].send(share_message)
                    clients[user].send(size_bytes)
                    clients[user].sendall(received)
            log_message("broadcast", sender, "ALL", f"[Image] {image_path}")
    except Exception as e:
        print("Image error:", e)

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    user = authenticate(conn)
    if user:
        connected = True
        try:
            while connected:
                raw = conn.recv(HEADER)
                try:
                    msg = decrypt_message(raw.decode())
                except UnicodeDecodeError as e:
                    print(e)
                    continue
                if msg == DISCONNECT_MESSAGE:
                    connected = False
                elif msg.startswith("/Image "):
                    route=msg.split(" ",1)[1]
                    image(conn,user,route)
                elif msg[0] == "@": #unicast
                    user2, msg2 = msg[1:].split(" ", 1)
                    unicast(user, user2, msg2)
                elif msg[0] == "!":
                    _, msg2 = msg.split(" ", 1)
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