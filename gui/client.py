import socket
import threading
import json
import random
from sympy import primerange, gcd
import queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESHandler:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
        return ciphertext, cipher.nonce

    def decrypt(self, ciphertext, nonce):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode("utf-8")

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
    def __init__(self, username, socket_obj, crypto):
        self.username = username
        self.s = socket_obj
        self.crypto = crypto
        self.active_users = []
        self.messagelog = {}
        self.response_queue = queue.Queue()
        self.aes_keys = {}

    def receive_messages(self):
        while True:
            try:
                msg = self.s.recv(4096).decode("utf-8")
                if msg:
                    response = json.loads(msg)
                    self.handle_server_response(response)
            except Exception as e:
                print(f"Receive error: {e}")
                break

    def handle_server_response(self, response):
        method = response.get("method")
        if method == "ACTIVE_USERS":
            self.active_users = response.get("users", [])
        elif method == "PUBLIC_KEY":
            self.response_queue.put(response)
        elif method == "AES_KEY":
            sender = response["from"]
            aes_key = self.crypto.decrypt(response["key"])
            self.aes_keys[sender] = AESHandler(int.to_bytes(aes_key, 16, "big"))
        elif method == "PRIVATE":
            sender = response["from"]
            ciphertext = bytes.fromhex(response["message"])
            nonce = bytes.fromhex(response["nonce"])
            aes_handler = self.aes_keys.get(sender)
            if aes_handler:
                message = aes_handler.decrypt(ciphertext, nonce)
                if sender not in self.messagelog:
                    self.messagelog[sender] = []
                self.messagelog[sender].append((sender, message))

    def request_handler(self, method, value):
        data = {
            "method": method,
            "username": self.username,
            "value": value
        }
        self.s.send(json.dumps(data).encode("utf-8"))

    def exchange_aes_key(self, username, recipient_public_key):
        aes_key = get_random_bytes(16)
        encrypted_key = self.crypto.encrypt(recipient_public_key, int.from_bytes(aes_key, "big"))
        self.aes_keys[username] = AESHandler(aes_key)
        data = {
            "method": "SEND_AES",
            "username": self.username,
            "to": username,
            "key": encrypted_key
        }
        self.s.send(json.dumps(data).encode("utf-8"))

    def send_message_streamlit(self, username, message):
        if username not in self.aes_keys:
            self.request_handler("GET_PUBLIC_KEY", username)
            try:
                response = self.response_queue.get(timeout=5)
                recipient_public_key = response["publickey"]
                self.exchange_aes_key(username, recipient_public_key)
            except queue.Empty:
                return "Failed to get public key"

        aes_handler = self.aes_keys[username]
        encrypted_message, nonce = aes_handler.encrypt(message)

        if username not in self.messagelog:
            self.messagelog[username] = []

        self.messagelog[username].append((self.username, message))

        data = {
            "method": "PRIVATE",
            "username": self.username,
            "to": username,
            "message": encrypted_message.hex(),
            "nonce": nonce.hex()
        }
        self.s.send(json.dumps(data).encode("utf-8"))
        return "Message sent"

    def get_chat_log(self, with_user):
        return self.messagelog.get(with_user, [])
