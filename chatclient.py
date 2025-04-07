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

SERVER_HOST = #Change this! THis is where the servers IP goes
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
        # Generate larger primes for p and q to ensure a sufficiently large N
        primes = list(primerange(10000, 50000))  # Larger primes for stability
        self.p = random.choice(primes)
        self.q = random.choice(primes)
        while self.p == self.q:  # Ensure p and q are distinct
            self.q = random.choice(primes)
        self.N = self.p * self.q  # RSA modulus

    def Eulers_totient_funktion(self):
        self.phi_N = (self.p - 1) * (self.q - 1)  # Euler's Totient Function

    def choose_e(self):
        # Select e such that gcd(e, phi_N) == 1
        self.e = random.randint(2, self.phi_N - 1)
        while gcd(self.e, self.phi_N) != 1:
            self.e = random.randint(2, self.phi_N - 1)

    def modulære_inverse(self, e, phi):
        # Extended Euclidean Algorithm for modular inverse
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
        # Compute d as the modular inverse of e
        self.d = self.modulære_inverse(self.e, self.phi_N)

    def genkey(self):
        self.choose_prim()
        self.Eulers_totient_funktion()
        self.choose_e()
        self.choose_d()

        # Validate keys to ensure correctness
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
        enkodet_besked = [ord(c) for c in besked]  # Convert message to Unicode
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
        self.messagelog = {}  # Stores chat history per user
        self.current_chat = None  # Track active private chat

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
        except:
            print("Error sending AES key to recipient.")
        return aes_handler

    def request_handler(self, method, message):
        data = {"method": method, "message": message}
        try:
            self.s.send(json.dumps(data).encode('utf-8'))
        except:
            print("Error sending request.")

    def send_message(self, username):
        self.current_chat = username

        # Retrieve recipient's public key from the server
        data_request = {"method": "GET_PUBLIC_KEY", "to": username}
        self.s.send(json.dumps(data_request).encode("utf-8"))
        response = json.loads(self.s.recv(BUFFER_SIZE).decode("utf-8"))
        recipient_public_key = response["publickey"]

        # Exchange AES key with recipient
        aes_handler = self.exchange_aes_key(username, recipient_public_key)

        if username not in self.messagelog:
            self.messagelog[username] = []

        while True:
            self.refresh_private_chat(username)
            message = input("> ")

            if message.lower() == "/back":
                self.current_chat = None
                return

            # Encrypt the message using AES
            encrypted_message, nonce = aes_handler.encrypt(message)

            self.messagelog[username].append((self.username, message))

            data = {
                "method": "PRIVATE",
                "username": self.username,
                "to": username,
                "message": encrypted_message.hex(),  # Convert to hex for safe transmission
                "nonce": nonce.hex()  # Send nonce along with message
            }
            try:
                self.s.send(json.dumps(data).encode('utf-8'))
            except:
                print("Error sending message.")



    def refresh_private_chat(self, username):
        os.system("cls" if os.name == "nt" else "clear")  # Clear terminal
        print(f"--- Private Chat with {username} ---\n")

        # Print chat history
        for sender, msg in self.messagelog[username]:
            print(f"{sender}: {msg}")

        print("\n(Type '/back' to return)")


    def receive_messages(self):
        aes_handler = None  # AES handler will be set after key exchange
        while True:
            try:
                message = self.s.recv(BUFFER_SIZE).decode('utf-8')
                if not message:
                    break

                parsed_data = json.loads(message)
                if parsed_data["method"] == "KEY_EXCHANGE":
                    # Decrypt AES key
                    aes_key_encrypted = parsed_data["aes_key"]
                    aes_key = None  # Initialize aes_key
                    try:
                        aes_key = bytes([pow(c, self.crypto.key["d"], self.crypto.key["N"]) for c in aes_key_encrypted])
                    except ValueError as e:
                        print(f"Error during RSA decryption: {e}")
                        print(f"Decrypted values: {[pow(c, self.crypto.key['d'], self.crypto.key['N']) for c in aes_key_encrypted]}")
                        # Handle the error gracefully, for example:
                        aes_key = None
                        return  # Exit the function or raise an error

                    # Ensure aes_key is valid
                    if aes_key is None:
                        raise ValueError("Failed to decrypt AES key!")

                    decrypted_values = [pow(c, self.crypto.key["d"], self.crypto.key["N"]) for c in aes_key_encrypted]
                    if not all(0 <= val <= 255 for val in decrypted_values):
                        raise ValueError("Decrypted values contain integers out of byte range!")



                    aes_handler = AEShandler()
                    aes_handler.aes_key = aes_key
                    print(f"\n🔑 AES key exchanged with {parsed_data['from']}.")

                elif parsed_data["method"] == "PRIVATE":
                    sender = parsed_data["from"]
                    encrypted_message = bytes.fromhex(parsed_data["message"])
                    nonce = bytes.fromhex(parsed_data["nonce"])

                    # Decrypt the message using AES
                    if aes_handler:
                        decrypted_message = aes_handler.decrypt(encrypted_message, nonce)

                        # Store and display
                        if sender not in self.messagelog:
                            self.messagelog[sender] = []
                        self.messagelog[sender].append((sender, decrypted_message))

                        if self.current_chat == sender:
                            self.refresh_private_chat(sender)
                    else:
                        print("Missing AES handler for decryption.")
                        # Notify only if user is not in chat
                        if self.current_chat != sender:
                            print(f"\n New message from {sender}! Type '/chat {sender}' to reply.")

                elif parsed_data["method"] == "POST":
                    if parsed_data["path"] == "usersview":
                        print("\nUsers Online:")
                        for key, value in parsed_data.items():
                            if key.startswith("user"):
                                print(value)
                    elif parsed_data["path"] == "active_users":
                        print("\nActive Users:")
                        users = parsed_data["users"]
                        if users:
                            for user in users:
                                if user != self.username:
                                    print(f"- {user}")
                        else:
                            print("No active users available.")

            except json.JSONDecodeError:
                print("Received invalid JSON data.")
            except Exception as e:
                print(f"Error receiving message: {e}")
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
                    print("Users Active right now:")
                    self.request_handler("GET", "active_users")
                    print("/back")
                    userconnect = input("\nEnter username for private chat: ")
                    if userconnect == "/back":
                        continue
                    else:
                        self.send_message(userconnect)
                elif cmd.lower() == "exit":
                    self.s.close()
                    exit()
        except (socket.error, KeyboardInterrupt):
            print("\nConnection lost. Attempting to reconnect...")
            self.s.close()
            exit()  # Let the main loop handle reconnection




if __name__ == "__main__":
    while True:  # Allow reconnecting if disconnected
        # Gather the username before initializing the handler
        username = input("Enter your username: ").strip()

        # Create the socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))

        # Perform the handshake with the server
        crypto = cryptohandler()  # Generate fresh RSA keys for each connection
        handshake = {
            "username": username,
            "publickey": (crypto.key["e"], crypto.key["N"])
        }
        s.send(json.dumps(handshake).encode("utf-8"))

        # Pass the username and socket to ChatHandler
        chat = ChatHandler(username, s, crypto)

        # Start listening for messages and run the command interface
        threading.Thread(target=chat.receive_messages, daemon=True).start()
        try:
            chat.command_turtle()
        except KeyboardInterrupt:
            print("\nDisconnected. Restarting...")
            s.close()
