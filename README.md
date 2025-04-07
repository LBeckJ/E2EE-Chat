# E2EE-Chat
Client and Server code for an End-2-End Encryption chat application. Written only with python.

# Explanation
This program uses socket to create a listening server that then handles connecting clients. The clients connect with socket aswell and have the option to see other clients connected to the server. When creating a new private chat with another client, then a AES key is encrypted with the reciving clients public RSA key. Where the AES key is sent over to the recipiant and decrypted by them. That AES key is then used by both clients to encrypt and decrypt messages sent back and forth. This results in the server only being able to see encrypted data and never recives a key in plaintext.
**This code is for a school project, so it shouldnt be used in a setting that is required of high security. (Only a proof of concept)**

# Usage
First install the requirements.txt with:

> pip install -r /path/to/requirements.txt

Then remember to change the port you want the server to listen on. If you change the port for the server, then you have to make sure to change which port the client is trying to connect with. 
The client will also have to have an updated **IP** which it is trying to connect to.

If you want to use the server and client over the open network and not locally, then you will have to configer portforwarding on the servers router and firewall.

**Run the server first, then the clients can connect afterwards.**
