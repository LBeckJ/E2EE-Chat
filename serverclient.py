import socket
import threading
import json
import os

users = []
active_users = {}
messagelog = {}
print_lock = threading.Lock()
buffersize = 1024

class UserConnection:
    def __init__(self, conn, addr, username, publickey):
        self.conn = conn
        self.addr = addr
        self.username = username
        self.rsaE, self.rsaN = publickey

    def append_info(self, threadid):
        user_info = {
            "threadid": threadid,
            "addr": self.addr,
            "username": self.username,
            "publickey": (self.rsaE, self.rsaN)
        }
        with print_lock:
            users.append(user_info)
            active_users[self.username] = self.conn
            messagelog[self.username] = {}  # Initialize empty chat log for user

    def threaded(self):
        try:
            while True:
                data = self.recv_message()
                if not data:
                    del active_users[self.username]
                    break  # Client disconnected

                if data["method"] == "GET":
                    self.handle_request(data)
                if data["method"] == "PRIVATE":
                    recipient = data["to"]
                    publickey = (self.rsaE, self.rsaN)
                    if recipient in active_users:
                        if recipient not in messagelog[self.username]:
                            messagelog[self.username][recipient] = []
                            messagelog[recipient][self.username] = []

                        message_data = {
                            "method": "PRIVATE",
                            "from": self.username,
                            "message": data["message"],
                            "nonce": data["nonce"],
                            "publickey": (publickey)
                        }
                        print(f"Relaying message: {message_data}")
                        active_users[recipient].send(json.dumps(message_data).encode("utf-8"))
                    else:
                        error_msg = {"method": "ERROR", "message": "User not online"}
                        self.conn.send(json.dumps(error_msg).encode("utf-8"))
                elif data["method"] == "GET_PUBLIC_KEY":
                    recipient = data["to"]
                    if recipient in active_users:
                        recipient_info = next(user for user in users if user["username"] == recipient)
                        response = {
                            "method": "PUBLIC_KEY",
                            "publickey": recipient_info["publickey"]
                        }
                        self.conn.send(json.dumps(response).encode("utf-8"))
                    else:
                        error_msg = {"method": "ERROR", "message": "User not online"}
                        self.conn.send(json.dumps(error_msg).encode("utf-8"))

                elif data["method"] == "KEY_EXCHANGE":
                    recipient = data["to"]
                    if recipient in active_users:
                        key_exchange_data = {
                            "method": "KEY_EXCHANGE",
                            "from": self.username,
                            "aes_key": data["aes_key"]
                        }
                        active_users[recipient].send(json.dumps(key_exchange_data).encode("utf-8"))
                    else:
                        error_msg = {"method": "ERROR", "message": "User not online"}
                        self.conn.send(json.dumps(error_msg).encode("utf-8"))

        except Exception as e:
            print(f"Error with {self.username}: {e}")
        finally:
            self.conn.close()
            with print_lock:
                if self.username in active_users:  # Check if user still exists in active_users
                    del active_users[self.username]
                users[:] = [u for u in users if u["username"] != self.username]
                print(f"User {self.username} disconnected (keys cleared)")


    def recv_message(self):
        try:
            data = self.conn.recv(buffersize).decode('utf-8')
            return json.loads(data) if data else None
        except json.JSONDecodeError:
            print("Invalid JSON received.")
            return None
        except Exception as e:
            print(f"Error receiving message from {self.username}: {e}")
            return None

    def handle_request(self, message):
        if message["message"] == "usersview":
            data = {"method": "POST", "path": "usersview"}
            with print_lock:
                for i, user in enumerate(users):
                    data[f"user{i}"] = f"User: {user['username']} | ID: {user['threadid']}"
            self.conn.send(json.dumps(data).encode('utf-8'))

        elif message["message"] == "active_users":
            with print_lock:
                data = {"method": "POST", "path": "active_users", "users": list(active_users.keys())}
            self.conn.send(json.dumps(data).encode('utf-8'))

        elif message["message"].startswith("chat_history:"):
            target_user = message["message"].split(":")[1]
            if target_user in messagelog[self.username]:
                data = {"method": "CHAT_HISTORY", "chat_with": target_user, "messages": messagelog[self.username][target_user]}
            else:
                data = {"method": "CHAT_HISTORY", "chat_with": target_user, "messages": []}
            self.conn.send(json.dumps(data).encode("utf-8"))


class Server:
    def __init__(self):
        self.server_host = "0.0.0.0"
        self.server_port = 5000
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind_socket()

    def bind_socket(self):
        try:
            self.s.bind((self.server_host, self.server_port))
            self.s.listen(5)
            print(f"Listening on {self.server_host}:{self.server_port}")
            self.accept_connections()
        except socket.error as msg:
            print(f"Socket binding error: {msg}, retrying...")
            self.bind_socket()

    def accept_connections(self):
        while True:
            conn, addr = self.s.accept()
            conn.setblocking(1)

            try:
                client_handshake = conn.recv(buffersize).decode("utf-8").strip()
                data = json.loads(client_handshake)
                
                # Handle reconnection: Refresh existing user data
                existing_user = next((u for u in users if u["username"] == data["username"]), None)
                if existing_user:
                    with print_lock:
                        users.remove(existing_user)  # Remove stale user data
                        if data["username"] in active_users:
                            del active_users[data["username"]]  # Clear active user record
                        print(f"Refreshing connection for user: {data['username']}")

                # Create new connection for the user
                new_user = UserConnection(conn, addr, data["username"], data["publickey"])
                new_user.append_info(threading.get_ident())

                print(f"New connection: {data['username']} from {addr[0]}")
                threading.Thread(target=new_user.threaded, daemon=True).start()
            except Exception as e:
                print(f"Error establishing connection: {e}")
                conn.close()


if __name__ == "__main__":
    Server()
