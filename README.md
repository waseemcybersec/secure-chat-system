# secure-chat-system
This project implements a secure client-server chat system using Diffie-Hellman key exchange to establish a shared secret and AES-128 CBC mode for encrypting communications. It supports user registration and login, where user credentials (email, username, and password) are transmitted securely after being encrypted.
# Features
## Diffie-Hellman Key Exchange: 
Ensures a secure key exchange between client and server.
## AES-128 CBC Encryption: 
Used to encrypt and decrypt sensitive information and chat messages.
## User Registration: 
Securely encrypts and stores user email, username, and hashed password with salt.
## User Login: 
Authenticates users by securely transmitting credentials and comparing hashed passwords.
## Encrypted Chat: 
After login, all communication between client and server is encrypted using the shared AES key.
# Libraries Used
## socket: 
For establishing and managing TCP connections between client and server.
## hashlib: 
Used for hashing passwords and deriving AES keys from the Diffie-Hellman shared secret.
## base64: 
To encode encrypted data for safe transmission.
## random: 
To generate private keys and salts.
## Crypto.Cipher.AES: 
For performing AES encryption and decryption in CBC mode.
## Crypto.Util.Padding: 
Adds/removes padding to the data for AES encryption.
# How It Works
## Key Exchange: 
Before registration or login, the client and server perform Diffie-Hellman key exchange to derive a shared AES-128 encryption key.
## Registration/Login:
Email, username, and password are encrypted using AES and sent to the server.
The server decrypts the credentials, hashes the password (with a salt), and securely stores it.
## Chat: 
Once logged in, all messages exchanged between the client and server are encrypted with the shared AES key.
# Files
## server.py: 
Implements the server-side logic, handles user registration, login, and chat using encrypted communication.
## client.py: 
Implements the client-side logic, including registration, login, and encrypted chat.
## creds.txt: 
A file where user credentials (email, username, and hashed password) are stored.
# Security Features
## Diffie-Hellman Key Exchange: 
Ensures that the AES key is securely exchanged between client and server without transmitting it over the network.
## AES-128 Encryption: 
Ensures the confidentiality of all sensitive data (email, username, password) during transmission and chat.
## Password Hashing with Salt: 
User passwords are securely hashed and stored with random salts, protecting against attacks like rainbow table attacks.
# Future Enhancements
Add two-factor authentication (2FA) for improved security.  
Implement session management for handling multiple clients and chat sessions.  
Expand to support group chats with secure multi-party key exchange.  
