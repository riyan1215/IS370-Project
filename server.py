import socket
import threading
import sqlite3
HEADER = 64
PORT = 5051
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
clients = {} #riyan -> conn || saad --> conn


def unicast(oguser, user, msg):
    if user in clients:
        msg = oguser + ':' + msg
        print(msg)
        clients[user].send(msg.encode(FORMAT))
    else:
        print("user is not connected")


def broadcast(user, msg2):
    for client in clients:
        msg2=f"[BROADCAST] {user}: {msg2}"
        clients[client].send(msg2.encode(FORMAT))


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    connected = True
    user = conn.recv(1024).decode()
    conn.send(b"User has Logged in Successfully")
    clients[user] = conn
    while connected:
        msg = conn.recv(1024).decode()
        if msg[0] == "@":
            user2, msg2 = msg[1:].split(" ", 1)
            unicast(user, user2, msg2)
        elif msg[0] == "!":
            u,msg2 = msg[1:].split(" ", 1)
            broadcast(user, msg2)
        elif msg == "/list":
            online_clients = "\n".join(clients.keys())
            conn.send(f"USER_LIST:\n{online_clients}".encode(FORMAT))
        if not msg:
            connected = False
        else:
            if msg != "/list":
                print(f"[{user}] {msg}")
    del clients[user]
def start():
    server.listen()
    print(f"[Listening] Server is Listening in {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
def list_clients():
    return clients.keys()

print("[STARTING] server is starting...")
start()
