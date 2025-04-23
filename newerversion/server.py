import socket
import threading
import json
import time

HOST = "0.0.0.0"
PORT = 1111
BUFFER_SIZE = 4096

clients = {}  # username -> {"socket": socket, "publickey": (e, N)}
clients_lock = threading.Lock()


def broadcast_active_users():
    with clients_lock:
        users = list(clients.keys())
        for username, data in clients.items():
            try:
                data["socket"].send(json.dumps({
                    "method": "POST",
                    "path": "active_users",
                    "users": users
                }).encode("utf-8"))
            except:
                continue


def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        handshake_data = conn.recv(BUFFER_SIZE).decode("utf-8")
        handshake = json.loads(handshake_data)
        username = handshake["username"]
        publickey = tuple(handshake["publickey"])

        with clients_lock:
            clients[username] = {
                "socket": conn,
                "publickey": publickey
            }

        while True:
            try:
                raw_data = conn.recv(BUFFER_SIZE)
                if not raw_data:
                    break

                data = json.loads(raw_data.decode("utf-8"))
                method = data.get("method")

                if method == "GET":
                    if data["message"] == "active_users":
                        with clients_lock:
                            active = list(clients.keys())
                        response = {
                            "method": "POST",
                            "path": "active_users",
                            "users": active
                        }
                        conn.send(json.dumps(response).encode("utf-8"))

                elif method == "GET_PUBLIC_KEY":
                    to_user = data["to"]
                    with clients_lock:
                        if to_user in clients:
                            pubkey = clients[to_user]["publickey"]
                            response = {
                                "method": "GET_PUBLIC_KEY",
                                "publickey": pubkey
                            }
                            conn.send(json.dumps(response).encode("utf-8"))
                        else:
                            response = {
                                "method": "ERROR",
                                "message": f"User '{to_user}' not found."
                            }
                            conn.send(json.dumps(response).encode("utf-8"))

                elif method == "KEY_EXCHANGE":
                    to_user = data["to"]
                    with clients_lock:
                        if to_user in clients:
                            recipient_conn = clients[to_user]["socket"]
                            forward = {
                                "method": "KEY_EXCHANGE",
                                "from": username,
                                "aes_key": data["aes_key"]
                            }
                            recipient_conn.send(json.dumps(forward).encode("utf-8"))

                elif method == "PRIVATE":
                    to_user = data["to"]
                    with clients_lock:
                        if to_user in clients:
                            recipient_conn = clients[to_user]["socket"]
                            forward = {
                                "method": "PRIVATE",
                                "from": username,
                                "message": data["message"],
                                "nonce": data["nonce"]
                            }
                            recipient_conn.send(json.dumps(forward).encode("utf-8"))
                        else:
                            conn.send(json.dumps({
                                "method": "ERROR",
                                "message": "Recipient not found."
                            }).encode("utf-8"))

                else:
                    conn.send(json.dumps({
                        "method": "ERROR",
                        "message": "Unknown method."
                    }).encode("utf-8"))

            except json.JSONDecodeError:
                conn.send(json.dumps({"method": "ERROR", "message": "Invalid JSON."}).encode("utf-8"))
            except Exception as e:
                print(f"[!] Error handling data from {addr}: {e}")
                break

    except Exception as e:
        print(f"[!] Initial handshake failed: {e}")
    finally:
        with clients_lock:
            disconnected_user = None
            for uname, info in list(clients.items()):
                if info["socket"] == conn:
                    disconnected_user = uname
                    del clients[uname]
                    break

        broadcast_active_users()
        conn.close()
        if disconnected_user:
            print(f"[-] {disconnected_user} disconnected.")
        else:
            print(f"[-] {addr} disconnected.")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"✅ Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()
