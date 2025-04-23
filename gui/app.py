import socket
import json
import random
import queue
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from sympy import primerange
from math import gcd
import streamlit as st

SERVER_HOST = "localhost"  # Server IP
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
        self.active_users = []  # List of active users from the server
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
            if self.s:
                self.s.send(json.dumps(data).encode('utf-8'))
        except (socket.error, OSError):
            print("Error sending request.")

    def fetch_active_users(self):
        data_request = {"method": "ACTIVE_USERS"}
        self.s.send(json.dumps(data_request).encode("utf-8"))

    def handle_active_users(self, data):
        # Update the active users list with the server response
        if "active_users" in data:
            self.active_users = data["active_users"]
            st.session_state.active_users = self.active_users  # Save in session_state
            st.session_state.page = 'active_users'

    def send_message(self, username):
        if not self.s:
            print("Socket is not initialized.")
            return

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
            message = st.text_input(f"Message to {username}: ", "")

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
                if self.s:
                    self.s.send(json.dumps(data).encode('utf-8'))
            except (socket.error, OSError):
                print("Connection error while sending message.")

    def refresh_private_chat(self, username):
        st.write(f"--- Private Chat with {username} ---\n")
        for sender, msg in self.messagelog[username]:
            st.write(f"{sender}: {msg}")
        st.write("\n(Type '/back' to return)")

    def receive_messages(self):
            while True:
                try:
                    message = self.s.recv(BUFFER_SIZE).decode('utf-8')
                    if not message:
                        break

                    parsed_data = json.loads(message)
                    if parsed_data["path"] == "active_users":
                        self.handle_active_users(parsed_data)
                    elif parsed_data["path"] == "publickey":
                        self.response_queue.put(parsed_data)
                    elif parsed_data["path"] == "aes_key":
                        sender = parsed_data["from"]
                        aes_key = parsed_data["key"]
                        aes_handler = AEShandler()
                        aes_handler.aes_key = aes_key
                        self.aes_keys[sender] = aes_handler
                    elif parsed_data["path"] == "private":
                        sender = parsed_data["from"]
                        ciphertext = bytes.fromhex(parsed_data["message"])
                        nonce = bytes.fromhex(parsed_data["nonce"])
                        aes_handler = self.aes_keys.get(sender)
                        if aes_handler:
                            message = aes_handler.decrypt(ciphertext, nonce)
                            if sender not in self.messagelog:
                                self.messagelog[sender] = []
                            self.messagelog[sender].append((sender, message))
                    elif parsed_data["path"] == "error":
                        st.error(parsed_data["message"])
                except (socket.error, OSError) as e:
                    print(f"Socket error: {e}")
                    break
                except json.JSONDecodeError:
                    print("Failed to decode JSON response.")
                    break

                except Exception:
                    break

    def run(self):
        # Page 1: Username input
        if 'page' not in st.session_state:
            st.session_state.page = 'username_input'

        # Page 1: Username input form
        if st.session_state.page == 'username_input':
            st.title("Enter your username")
            username_input = st.text_input("Enter username", "")
            if username_input:
                st.session_state.username = username_input.strip()
                st.session_state.page = 'active_users'

        # Page 2: Display active users
        elif st.session_state.page == 'active_users':
            if 's' not in st.session_state:
                # Initialize connection and crypto here
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((SERVER_HOST, SERVER_PORT))

                # Initialize the crypto handler and handshake
                crypto = cryptohandler()
                handshake = {"username": st.session_state.username, "publickey": (crypto.key["e"], crypto.key["N"])}
                s.send(json.dumps(handshake).encode("utf-8"))

                st.session_state.s = s
                st.session_state.chat = ChatHandler(st.session_state.username, s, crypto)

                # Start receiving messages in a separate thread
                threading.Thread(target=st.session_state.chat.receive_messages, daemon=True).start()

                # Fetch the active users from the server
                st.session_state.chat.fetch_active_users()

            st.title(f"Active Users - {st.session_state.username}")

            # Display the active users list if it exists
            if 'active_users' in st.session_state and st.session_state.active_users:
                st.write("Click on a user to start a private chat:")
                for user in st.session_state.active_users:
                    if st.button(user):
                        # Start a private chat with selected user
                        st.session_state.chat.send_message(user)
                        st.session_state.page = 'private_chat'
            else:
                st.write("No active users available.")

        # Page 3: Private chat (if a user selects someone to chat with)
        elif st.session_state.page == 'private_chat':
            st.title(f"Private Chat with {st.session_state.chat.current_chat}")
            message = st.text_input("Enter message")
            if message:
                st.session_state.chat.send_message(st.session_state.chat.current_chat)

            # Display the chat log
            st.write(f"Chat with {st.session_state.chat.current_chat}:")
            for sender, msg in st.session_state.chat.messagelog.get(st.session_state.chat.current_chat, []):
                st.write(f"{sender}: {msg}")

            # Add option to go back
            if st.button("Back"):
                st.session_state.page = 'active_users'

if __name__ == "__main__":
    chat = ChatHandler(None, None, None)
    chat.run()