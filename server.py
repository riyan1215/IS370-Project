import copy
import os
import socket
import threading
from datetime import datetime

from database import check_user, login, group_members, groups
from encryption import encrypt_message, decrypt_message

HEADER = 1024
PORT = 5051
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "/DISCONNECT"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
client_lock=threading.Lock()
log_lock=threading.Lock()
clients = {}  # user-->connection


def log_message(log_type, sender, receiver_or_group, message):
    with log_lock:
        os.makedirs("logs/unicast", exist_ok=True)
        os.makedirs("logs/multicast", exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if log_type == "unicast":
            sorted_users = sorted([sender, receiver_or_group])
            filename = f"unicast/{sorted_users[0]}_{sorted_users[1]}.txt"
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
        username_check = check_user(username)
        if username_check:
            conn.sendall(b"200")  # correct username
            password = conn.recv(HEADER).decode()
            check_password = login(username, password)
            with client_lock:
                if check_password and username not in clients.keys():
                    conn.sendall(b"200")  # correct password
                    clients[username] = conn
                    return username
                elif username in clients.keys():
                    conn.sendall(b"409")  # "409 stands for conflict", already logged in
                    continue
                else:
                    conn.sendall(b"401")  # incorrect password or already logged in
                    continue
        else:
            conn.sendall(b"404")  # incorrect username


def unicast(sender, receiver, msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # it's not really accurate, but it's good enough
    with client_lock:
        client_local = clients.copy()

    if receiver in client_local:
        full_msg = f"[{timestamp}] {sender} ➔ {receiver} :: {msg}"
        clients[receiver].sendall(encrypt_message(full_msg).encode(FORMAT))
        log_message("unicast", sender, receiver, msg)
    else:
        print("user is not connected")


def broadcast(sender, msg):
    with client_lock:
        client_local=clients.copy()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {sender} ➔ ALL :: {msg}"
    for client in client_local:
        if client is not sender:
            clients[client].sendall(encrypt_message(full_msg).encode(FORMAT))
    log_message("broadcast", sender, "ALL", msg)


def multicast(sender, group, msg):
    with client_lock:
        client_local=clients.copy()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {sender} ➔ GROUP [{group}] :: {msg}"
    group_names = group_members(group)
    for user in group_names:
        if user != sender and user in client_local:
            clients[user].sendall(encrypt_message(full_msg).encode(FORMAT))
            log_message("multicast", sender, group, msg)


def send_image(share_message,size_bytes,image_path,sender,route=None,received=None):
    with client_lock:
        client_local = clients.copy()
    if route and route.startswith("@"):
        user = route[1:]
        if user in client_local:
            client_local[user].sendall(share_message)
            client_local[user].sendall(size_bytes)
            for i in range(0, len(received), HEADER):
                client_local[user].sendall(received[i:i + HEADER])
            log_message("unicast", sender, user, f"[Image] {image_path}")
    elif route and route.startswith("#"):
        group = route[1:]
        members = group_members(group)
        for user in members:
            if user != sender and user in client_local:
                client_local[user].sendall(share_message)
                client_local[user].sendall(size_bytes)
                for i in range(0, len(received), HEADER):
                    client_local[user].sendall(received[i:i + HEADER])

        log_message("multicast", sender, group, f"[Image] {image_path}")
    elif route and route.startswith("All"):
        for user in client_local:
            if user != sender:
                client_local[user].sendall(share_message)
                client_local[user].sendall(size_bytes)
                for i in range(0, len(received), HEADER):
                    client_local[user].sendall(received[i:i + HEADER])

        log_message("broadcast", sender, "ALL", f"[Image] {image_path}")
    else:
        if sender in client_local:
            client_local[sender].sendall(size_bytes)
            for i in range(0, len(received), HEADER):
                client_local[sender].sendall(received[i:i + HEADER])


def image(conn, sender, route=None, image_path=None):
    try:
        os.makedirs("logs/images", exist_ok=True)
        print(image_path)
        if route:
            # Receive 4 bytes for size
            size_bytes = conn.recv(4)
            size = int.from_bytes(size_bytes, 'big')
            # Receive image data
            received = b""
            while len(received) < size:
                chunk = conn.recv(min(size - len(received), HEADER))
                if not chunk:
                    break
                received += chunk
            # Save image
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            image_path = f"logs/images/{sender}_{timestamp}.jpg"
            
            # Write the file in a single operation with write mode
            with open(image_path, "wb") as f:
                with log_lock:
                    f.write(received)
            share_message = encrypt_message('/Image:').encode(FORMAT)

        else:
            print(image_path)
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image file not found: {image_path}")

            with open(image_path, "rb") as f:
                with log_lock:
                    received = f.read()
            size_bytes = len(received).to_bytes(4, 'big')
            share_message=None

        send_image(route=route, share_message=share_message, size_bytes=size_bytes,
                   received=received, image_path=image_path, sender=sender)
    except Exception as e:
        print("Image error:", e)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    user = authenticate(conn)
    if user:
        connected = True  # after this notify all users that a new user has joined,
        # maybe send the new one only?, but that will not delete the one who signed out
        list_refresh()
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
                    route = msg.split(" ", 1)[1]
                    image(conn, user, route)
                elif msg[0] == "@":  # unicast
                    user2, msg2 = msg[1:].split(" ", 1)
                    unicast(user, user2, msg2)
                elif msg[0] == "!":
                    _, msg2 = msg.split(" ", 1)
                    broadcast(user, msg2)
                elif msg[0] == "#":
                    group, msg = msg[1:].split(" ", 1)
                    multicast(user, group, msg)
                elif msg.startswith("/img_log"):
                    _,path=msg.split(" ")
                    image(conn,user,image_path=path)


                elif msg.startswith("/get_history"):
                    # Example usage: /get_history unicast otheruser
                    parts = msg.split()
                    history_type = parts[1]
                    if history_type == "broadcast":
                        log_file = "logs/broadcast.txt"
                    elif history_type == "unicast" and len(parts) == 3:
                        peer = parts[2]
                        list1 = sorted([user, peer])
                        log_file = f"logs/unicast/{list1[0]}_{list1[1]}.txt"
                    elif history_type == "multicast" and len(parts) == 3:
                        group = parts[2]
                        log_file = f"logs/multicast/{group}.txt"
                    else:
                        conn.sendall(encrypt_message("/history_error").encode(FORMAT))
                        continue
                    try:
                        if os.path.exists(log_file):
                            with open(log_file, "r", encoding="utf-8") as f:
                                with log_lock:
                                    history_content = f.read()
                                # Split in parts if too long for one send, else send whole file
                                # Split and send in chunks
                                conn.sendall(encrypt_message(f"/history:").encode(FORMAT))
                                encoded_history = encrypt_message(history_content).encode(FORMAT)
                                size_bytes = len(encoded_history).to_bytes(4, 'big')
                                conn.sendall(size_bytes)

                                for i in range(0, len(encoded_history), HEADER):
                                    chunk = encoded_history[i:i + HEADER]
                                    conn.sendall(chunk)

                                conn.sendall(encrypt_message("/history_end").encode(FORMAT))
                        else:
                            conn.sendall(encrypt_message("No history found.").encode(FORMAT))
                    except Exception as e:
                        conn.sendall(encrypt_message(f"Server error: {e}").encode(FORMAT))
        except Exception as e:
            print(f"[ERROR] Exception with user {user}: {e}")
        finally:
            print(f"[{user}] Disconnected")
            if user in clients:
                del clients[user]
                list_refresh()  # not the best way it should, the best way is to send a message to all users that the user left
            conn.close()
    else:
        conn.close()


def list_refresh():
    with client_lock:
        client_copy=clients.copy()
    user_list = [f"@{u}" for u in client_copy.keys()]
    for user, conn in client_copy.items():
        user_groups = groups(user)
        group_list = ["#" + g for g in user_groups] if user_groups else []
        combined = "\n".join(user_list + group_list)
        encrypted_userlist = encrypt_message(f"USER_LIST:\n{combined}")
        conn.sendall(encrypted_userlist.encode(FORMAT))


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