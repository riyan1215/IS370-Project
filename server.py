import socket
import threading
from database import check_user,login,group_members,groups
HEADER = 1024
PORT = 5051
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "DISCONNECT"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
clients = {} #user-->connection

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
        msg = oguser + ':' + msg
        print(msg)
        clients[user].send(msg.encode(FORMAT))
    else:
        print("user is not connected")


def broadcast(user, msg2):
    msg2=f"[BROADCAST] {user}: {msg2}"
    for client in clients:
        clients[client].send(msg2.encode(FORMAT))


def multicast(group, msg2,oguser):
    group_names=group_members(group)
    print(group)
    msg2 =f'#{group} {oguser}: {msg2}'
    for user in group_names:
        if user != oguser and user in clients:
            clients[user].send(msg2.encode(FORMAT))


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    user = authenticate(conn)
    if user:
        connected = True
        try:
            while connected:
                    msg = conn.recv(HEADER).decode()
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
                        conn.send(f"USER_LIST:\n{combined}".encode(FORMAT))
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
