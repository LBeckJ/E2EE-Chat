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

    def encrypt_bytes(self, byte_data, recipient_N, recipient_e):
        return [pow(b, recipient_e, recipient_N) for b in byte_data]

    def decrypt_bytes(self, encrypted_data):
        decrypted = [pow(c, self.key["d"], self.key["N"]) for c in encrypted_data]
        return bytes(decrypted)



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
        aes_key_encrypted = self.crypto.encrypt_bytes(aes_handler.aes_key, recipient_public_key[1], recipient_public_key[0])

        data = {
            "method": "KEY_EXCHANGE",
            "to": recipient_username,
            "aes_key": aes_key_encrypted
        }
        try:
            self.s.send(json.dumps(data).encode('utf-8'))
            self.aes_keys[recipient_username] = aes_handler
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
        data_request = {"method": "GET", "message": "active_users"}
        self.s.send(json.dumps(data_request).encode("utf-8"))

    def handle_active_users(self, data):
        # Update the active users list with the server response
        self.active_users = data["users"]

    def getkey(self, username):
        if not self.s:
            print("Socket is not initialized.")
            return
        
        data_request = {"method": "GET_PUBLIC_KEY", "to": username}
        self.s.send(json.dumps(data_request).encode("utf-8"))

        try:
            response = self.response_queue.get(timeout=5)
            recipient_public_key = response["publickey"]
        except queue.Empty:
            print("Failed to receive public key.")
            return

        self.exchange_aes_key(username, recipient_public_key)

        if username not in self.messagelog:
            self.messagelog[username] = []

    def send_message(self, username, message):
        aes_handler = self.aes_keys[username]
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
                    print(f"Just recived message from server: {parsed_data}")

                    path = parsed_data.get("path")
                    method = parsed_data.get("method")

                    if path == "active_users":
                        self.handle_active_users(parsed_data)
                    elif method == "GET_PUBLIC_KEY":
                        print("In get public key")
                        self.response_queue.put(parsed_data)
                        print("Data put in queue")
                    elif method == "KEY_EXCHANGE":
                        print("in")
                        sender = parsed_data["from"]
                        aes_key = parsed_data["aes_key"]
                        aes_key = self.crypto.decrypt_bytes(aes_key)
                        print(f"Recived key from {sender}: {aes_key}")
                        aes_handler = AEShandler()
                        aes_handler.aes_key = aes_key
                        self.aes_keys[sender] = aes_handler
                        print("hit")
                    elif method == "PRIVATE":
                        sender = parsed_data["from"]
                        ciphertext = bytes.fromhex(parsed_data["message"])
                        nonce = bytes.fromhex(parsed_data["nonce"])
                        aes_handler = self.aes_keys[sender]
                        if aes_handler:
                            print(f"Found aes handler for {sender}: {aes_handler}")
                            try:
                                message = aes_handler.decrypt(ciphertext, nonce)
                                print(f"Decrypted message {message}")
                                if sender not in self.messagelog.keys():
                                    self.messagelog[sender] = []
                                self.messagelog[sender].append((sender, message))
                                print(f"Added to message log: {self.messagelog[sender]}")
                                st.rerun()
                            except Exception as e:
                                print(f"When decrypting: {e}")
                        else:
                            print(f"No aes handler for {sender}")
                            print(self.aes_keys)
                    elif method == "ERROR":
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
                try:
                    st.write("Connecting to server and setting up handshake...")
                    st.session_state.username = username_input.strip()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((SERVER_HOST, SERVER_PORT))
                    crypto = cryptohandler()
                    
                    handshake = {
                        "username": st.session_state.username,
                        "publickey": (crypto.key["e"], crypto.key["N"])
                    }
                    s.send(json.dumps(handshake).encode("utf-8"))

                    chat = ChatHandler(st.session_state.username, s, crypto)
                    st.session_state.s = s
                    st.session_state.chat = chat
                    threading.Thread(target=chat.receive_messages, daemon=True).start()
                    
                    st.session_state.page = 'active_users'
                    st.rerun()
                except:
                    st.session_state.page == '404'
                    st.rerun()

        # Page 2: Display active users
        elif st.session_state.page == 'active_users':
            st.session_state.chat.fetch_active_users()
            st.title(f"Active Users - {st.session_state.username}")
            if st.button("Refresh active users", type="primary"):
                st.session_state.chat.fetch_active_users()
                st.rerun()

            # Display the active users list if it exists
            if st.session_state.chat.active_users != []:
                st.write("Click on a user to start a private chat:")
                
                for user in st.session_state.chat.active_users:
                    if user != st.session_state.username:
                        if st.button(user, type="secondary"):
                            # Start a private chat with selected user
                            if user not in st.session_state.chat.aes_keys:
                                st.session_state.chat.getkey(user)
                            st.session_state.chat.current_chat = user
                            st.session_state.page = 'private_chat'
                            st.rerun()
            else:
                st.write("No active users available.")

        # Page 3: Private chat (if a user selects someone to chat with)
        elif st.session_state.page == 'private_chat':
            st.title(f"Private Chat with {st.session_state.chat.current_chat}")

            # Display the chat log
            st.write(f"Chat with {st.session_state.chat.current_chat}:")

            for sender, msg in st.session_state.chat.messagelog.get(st.session_state.chat.current_chat, []):
                    st.write(f"{sender}: {msg}")

            def submit():
                print("sending")
                st.session_state.chat.send_message(st.session_state.chat.current_chat, st.session_state.widget)
                st.session_state.widget = ""

            #Chat input
            st.text_input("Enter message", key="widget", on_change=submit)

            if st.button("Refresh chat log"):
                st.rerun()

            # Add option to go back
            if st.button("Back"):
                st.session_state.page = 'active_users'
                st.rerun()
        
        #404 page
        elif st.session_state.page == '404':
            st.title("404 page something went wrong")


if __name__ == "__main__":
    chat = ChatHandler(None, None, None)
    chat.run()
