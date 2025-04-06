import socket
import sys
import threading
HEADER = 256
PORT = 5051
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


def receive():
    while True:
        try:
            message = client.recv(1024).decode(FORMAT)
            if message:
                if ":" in message:
                    user, msg = message.split(":", 1)
                    print(f"\r[{user}] {msg}\nEnter Message: ", end="")
                else:
                    print(f"\n{message}")
        except Exception as e:
            print(f"An error occurred while receiving message: {e}")
            client.close()
            break


def send(msg):
    client.send(msg.encode(FORMAT))


user = input("Enter Username: ")
send(user)
message_back = client.recv(1024).decode(FORMAT)
print(message_back)

if message_back == "user unrecognized":
    sys.exit()
else:
    receive_thread = threading.Thread(target=receive, daemon=True)
    receive_thread.start()

    while True:
        msg = input("Enter Message: ")
        if msg == "":
            break
        send(msg)
    client.close()
