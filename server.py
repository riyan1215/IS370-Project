import socket
import threading

HEADER = 64
PORT = 5051
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
clients = {}
user_db = {
    "riyan": "123",
    "saad": "123",
}


def unicast(oguser, user, msg):
    if user in clients:
        msg = oguser + ':' + msg
        print(msg)
        clients[user].send(msg.encode(FORMAT))
    else:
        print("user is not connected")


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    connected = True
    user = conn.recv(1024).decode()
    if user.lower() in user_db:
        conn.send(b"User has Logged in Successfully")
        clients[user] = conn
        while connected:
            msg = conn.recv(1024).decode()
            if msg[0] == "@":
                user2, msg2 = msg[1:].split(" ", 1)
                unicast(user, user2, msg2)
            if not msg:
                connected = False
            else:
                print(f"[{user}] {msg}")

        print(f'[{user}] Disconnected')
    else:
        conn.send(b"user unrecognized")
        print(f"{user} is Not Registered")
    del clients[user]
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
