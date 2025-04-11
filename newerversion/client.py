import socket
import threading
import json
import os
from time import sleep
import random
from sympy import primerange
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from math import gcd
import queue

SERVER_HOST = "" #Server IP
SERVER_PORT = 1111
BUFFER_SIZE = 1024

class AEShandler:
    def __init__(self):
        self.aes_key = get_random_bytes(16)

    def encrypt(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_CTR)
        ciphertext = cipher.encrypt(message.encode("utf-8"))
        return ciphertext, cipher.nonce

    def decrypt(self, data, nonce):
        cipher = AES.new(self.aes_key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(data).decode('utf-8')

class cryptohandler:
    def __init__(self):
        self.key = self.genkey()

    def choose_prim(self):
        primes = list(primerange(10000, 50000))
        self.p = random.choice(primes)
        self.q = random.choice(primes)
        while self.p == self.q:
            self.q = random.choice(primes)
        self.N = self.p * self.q

    def Eulers_totient_funktion(self):
        self.phi_N = (self.p - 1) * (self.q - 1)

    def choose_e(self):
        self.e = random.randint(2, self.phi_N - 1)
        while gcd(self.e, self.phi_N) != 1:
            self.e = random.randint(2, self.phi_N - 1)

    def modulære_inverse(self, e, phi):
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, x, y = egcd(b % a, a)
            return g, y - (b // a) * x, x

        g, x, _ = egcd(e, phi)
        if g != 1:
            raise Exception("Modular inverse does not exist")
        return x % phi

    def choose_d(self):
        self.d = self.modulære_inverse(self.e, self.phi_N)

    def genkey(self):
        self.choose_prim()
        self.Eulers_totient_funktion()
        self.choose_e()
        self.choose_d()

        if self.N <= 255:
            raise ValueError("RSA modulus (N) is too small!")
        if gcd(self.e, self.phi_N) != 1:
            raise ValueError("Public exponent (e) is not coprime with phi_N!")

        keys = {
            "N": self.N,
            "e": self.e,
            "d": self.d
        }
        return keys

    def encrypt(self, besked, recipiant_N, recipiant_e):
        enkodet_besked = [ord(c) for c in besked]
        enkrypteret_besked = [pow(c, recipiant_e, recipiant_N) for c in enkodet_besked]
        return enkrypteret_besked

    def decrypt(self, besked):
        decrypted_msg = [pow(c, self.key["d"], self.key["N"]) for c in besked]
        if not all(0 <= val <= 255 for val in decrypted_msg):
            raise ValueError("Decrypted values contain integers out of byte range!")
        return "".join(chr(c) for c in decrypted_msg)


class ChatHandler:
    def __init__(self, username, connection, crypto):
        self.username = username
        self.s = connection
        self.crypto = crypto
        self.messagelog = {}
        self.active_users = []
        self.current_chat = None
        self.user_typing = False
        self.aes_keys = {}  # Stores AES handler per user
        self.response_queue = queue.Queue()

    def exchange_aes_key(self, recipient_username, recipient_public_key):
        aes_handler = AEShandler()
        aes_key_encrypted = [pow(byte, recipient_public_key[0], recipient_public_key[1]) for byte in aes_handler.aes_key]

        data = {
            "method": "KEY_EXCHANGE",
            "to": recipient_username,
            "aes_key": aes_key_encrypted
        }
        try:
            self.s.send(json.dumps(data).encode('utf-8'))
        except (socket.error, OSError):
            print("Error sending AES key to recipient.")
        self.aes_keys[recipient_username] = aes_handler

    def request_handler(self, method, message):
        data = {"method": method, "message": message}
        try:
            self.s.send(json.dumps(data).encode('utf-8'))
        except (socket.error, OSError):
            print("Error sending request.")

    def send_message(self, username):
        self.current_chat = username

        data_request = {"method": "GET_PUBLIC_KEY", "to": username}
        self.s.send(json.dumps(data_request).encode("utf-8"))

        try:
            response = self.response_queue.get(timeout=5)
            recipient_public_key = response["publickey"]
        except queue.Empty:
            print("Failed to receive public key.")
            return

        self.exchange_aes_key(username, recipient_public_key)
        aes_handler = self.aes_keys[username]

        if username not in self.messagelog:
            self.messagelog[username] = []

        self.user_typing = True
        while True:
            if not self.current_chat:
                self.user_typing = False
                return

            self.refresh_private_chat(username)
            try:
                message = input("> ")
            except EOFError:
                print("Input interrupted. Returning to main menu.")
                self.user_typing = False
                break

            if message.lower() == "/back":
                self.current_chat = None
                self.user_typing = False
                return

            encrypted_message, nonce = aes_handler.encrypt(message)

            self.messagelog[username].append((self.username, message))

            data = {
                "method": "PRIVATE",
                "username": self.username,
                "to": username,
                "message": encrypted_message.hex(),
                "nonce": nonce.hex()
            }
            try:
                self.s.send(json.dumps(data).encode('utf-8'))
            except (socket.error, OSError):
                print("Connection error while sending message.")

    def refresh_private_chat(self, username):
        os.system("cls" if os.name == "nt" else "clear")
        print(f"--- Private Chat with {username} ---\n")
        for sender, msg in self.messagelog[username]:
            print(f"{sender}: {msg}")
        print("\n(Type '/back' to return)")

    def receive_messages(self):
        while True:
            try:
                message = self.s.recv(BUFFER_SIZE).decode('utf-8')
                if not message:
                    break

                parsed_data = json.loads(message)
                if parsed_data["method"] == "KEY_EXCHANGE":
                    sender = parsed_data["from"]
                    aes_key_encrypted = parsed_data["aes_key"]
                    aes_key = bytes([pow(c, self.crypto.key["d"], self.crypto.key["N"]) for c in aes_key_encrypted])
                    if not all(0 <= val <= 255 for val in aes_key):
                        continue

                    aes_handler = AEShandler()
                    aes_handler.aes_key = aes_key
                    self.aes_keys[sender] = aes_handler
                    print(f"\n AES key exchanged with {sender}.")

                elif parsed_data["method"] == "PRIVATE":
                    sender = parsed_data["from"]
                    encrypted_message = bytes.fromhex(parsed_data["message"])
                    nonce = bytes.fromhex(parsed_data["nonce"])
                    aes_handler = self.aes_keys.get(sender)
                    if aes_handler:
                        decrypted_message = aes_handler.decrypt(encrypted_message, nonce)
                        if sender not in self.messagelog:
                            self.messagelog[sender] = []
                        self.messagelog[sender].append((sender, decrypted_message))
                        if self.current_chat == sender and not self.user_typing:
                            self.refresh_private_chat(sender)
                    else:
                        print(f"\n New message from {sender}, but AES key not available.")

                elif parsed_data["method"] == "POST":
                    if parsed_data["path"] == "usersview":
                        print("\nUsers Online:")
                        for key, value in parsed_data.items():
                            if key.startswith("user"):
                                print(value)
                    elif parsed_data["path"] == "active_users":
                        self.active_users = parsed_data.get("users", [])
                        print("\nActive Users:")
                        if self.active_users:
                            for user in self.active_users:
                                if user != self.username:
                                    print(f"- {user}")
                        else:
                            print("No active users available.")
                
                elif parsed_data["method"] == "PUBLIC_KEY":
                    self.response_queue.put(parsed_data)

            except (json.JSONDecodeError, ConnectionResetError, socket.timeout):
                continue
            except Exception:
                break

    def command_turtle(self):
        try:
            while True:
                os.system("cls" if os.name == "nt" else "clear")
                print(f"Logged in as {self.username}")
                print("1: View active users")
                print("2: Enter private chat")
                print("exit: Disconnect")

                cmd = input("cmd: ").strip()
                if cmd == "1":
                    self.request_handler("GET", "active_users")
                    sleep(1)
                elif cmd == "2":
                    self.request_handler("GET", "active_users")
                    sleep(1)

                    users = self.active_users
                    if not users:
                        print("No active users found.")
                        sleep(2)
                        continue

                    print("\nActive Users:")
                    for user in users:
                        if user != self.username:
                            print(f"- {user}")

                    print("\n/back to return to menu")
                    userconnect = input("\nEnter username for private chat: ").strip()

                    if userconnect == "/back":
                        continue

                    if userconnect in users and userconnect != self.username:
                        self.send_message(userconnect)
                    else:
                        print(f"User '{userconnect}' is not online.")
                        sleep(2)

                elif cmd.lower() == "exit":
                    self.s.close()
                    exit()
        except (socket.error, KeyboardInterrupt):
            print("\nConnection lost. Attempting to reconnect...")
            self.s.close()
            exit()


if __name__ == "__main__":
    while True:
        username = input("Enter your username: ").strip()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))

        crypto = cryptohandler()
        handshake = {
            "username": username,
            "publickey": (crypto.key["e"], crypto.key["N"])
        }
        s.send(json.dumps(handshake).encode("utf-8"))

        chat = ChatHandler(username, s, crypto)
        threading.Thread(target=chat.receive_messages, daemon=True).start()
        try:
            chat.command_turtle()
        except KeyboardInterrupt:
            print("\nDisconnected. Restarting...")
            s.close()
