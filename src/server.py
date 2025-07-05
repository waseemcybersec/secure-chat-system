import socket

import os

import hashlib

import base64

import random

from Crypto.Cipher import AES

from Crypto.Util.Padding import pad, unpad



#file to store credentials

CREDENTIALS_FILE = "creds.txt"

P = 23 

G = 5 



def save_credentials(email, username, hashed_password, salt):

    with open(CREDENTIALS_FILE, 'a') as File:

        File.write(f"{email},{username},{hashed_password},{salt}\n")



def is_username_exists(username):

    if not os.path.exists(CREDENTIALS_FILE):

        return False

    with open(CREDENTIALS_FILE, 'r') as f:

        for line in f:

            if line.split(',')[1] == username:

                return True

    return False



def is_email_exists(email):

    if not os.path.exists(CREDENTIALS_FILE):

        return False

    with open(CREDENTIALS_FILE, 'r') as f:

        for line in f:

            if line.split(',')[0] == email:

                return True

    return False



def is_valid_email(email):

    # checking is the email valid or not

    return email.endswith('@gmail.com')  # endswith is a built in method for string



def hash_password(password, salt):

    byte = (password + salt).encode('utf-8')  # converting into bytes

    Hash = hashlib.sha256(byte)  # making hash

    string = Hash.hexdigest()  # converting back into hexadecimal digest

    return string



def register_user(client_socket):

    # first receive registration details -> email, username and password

    data = client_socket.recv(1024)

    decode_data = data.decode('utf-8')

    email, username, password = decode_data.split(',')

    

    if not is_valid_email(email):

        msg = ("Email must be a valid Gmail address")

        encoded_msg = msg.encode('utf-8')

        client_socket.send(encoded_msg)

        return False

        

    if is_username_exists(username):

        msg = ("username already exists")

        encoded_msg = msg.encode('utf-8')

        client_socket.send(encoded_msg)

        return False



    if is_email_exists(email): #it will call the is_email_exists and wait for a boolean return, and if true the following line run 

        msg = ("Email already exists")

        encoded_msg = msg.encode('utf-8')

        client_socket.send(encoded_msg)

        return False

    

    # generating a random salt

    salt = str(random.randint(100000, 999999))

    

    # hashing the password with the salt

    hashed_password = hash_password(password, salt)  # calling hash_password function

    

    # saving the credentials

    save_credentials(email, username, hashed_password, salt)  # calling save credential function

    

    client_socket.send("Registration successful".encode('utf-8'))

    return True



def verify_login(username, password):

    with open(CREDENTIALS_FILE, 'r') as f:

        for line in f:

            stored_email, stored_username, stored_hashed_password, stored_salt = line.strip().split(',')

            if stored_username == username:

                

                hashed_password = hash_password(password, stored_salt)

                return hashed_password == stored_hashed_password

    return False



def login_user(client_socket):

    data = client_socket.recv(1024)

    decode_data = data.decode('utf-8')

    username, password = decode_data.split(',')

    

    if verify_login(username, password):

        msg = ("Login successfull")

        encoded_msg = msg.encode('utf-8')

        client_socket.send(encoded_msg)

        return True

    else:

        msg = ("Login failed")

        encoded_msg = msg.encode('utf-8')

        client_socket.send(encoded_msg)

        return False



def diffie_hellman_exchange(client_socket):

    #receive client public key

    data = client_socket.recv(1024)

    decoded_data = data.decode('utf-8')

    client_public = int(decoded_data)



    

    #generating serverr private and public keys

    server_private = random.randint(1000, 9999)

    server_public = pow(G, server_private, P)

    

    # send server public key to client

    server_public_str = str(server_public)

    encoded_server_public = server_public_str.encode('utf-8')

    client_socket.send(encoded_server_public)



    

    # calculating shared key

    shared_key = pow(client_public, server_private, P)

    

    # convert shared key to bytes and pad to 16 bytes for aes

    shared_key_str = str(shared_key)

    encoded_shared_key = shared_key_str.encode()

    hashed_key = hashlib.sha256(encoded_shared_key).digest()

    aes_key = hashed_key[:16]



    return aes_key



def aes_encrypt(message, key):

    cipher = AES.new(key, AES.MODE_CBC)

    message_bytes = message.encode('utf-8')

    padded_message = pad(message_bytes, AES.block_size)

    ciphertext = cipher.encrypt(padded_message)

    encoded_ciphertext = base64.b64encode(cipher.iv + ciphertext)

    return encoded_ciphertext.decode('utf-8')



def aes_decrypt(ciphertext, key):

    decoded_ciphertext = base64.b64decode(ciphertext) #decoded back to original byte formaat from base 64

    iv = decoded_ciphertext[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted_message = decoded_ciphertext[16:]

    decrypted_message = cipher.decrypt(encrypted_message)

    plaintext = unpad(decrypted_message, AES.block_size)

    return plaintext.decode('utf-8')



def handle_client(client_socket):

    while True:

        recived_data = client_socket.recv(1024)  # receive up to 1024 byte/ 1MB data 

        option = recived_data.decode('utf-8')  # convert back to integer

        

        if option == '1':

            register_user(client_socket)

        elif option == '2':

            if login_user(client_socket):

                aes_key = diffie_hellman_exchange(client_socket)

                while True:

                    received_data = client_socket.recv(1024)

                    encrypted_message = received_data.decode('utf-8')



                    if encrypted_message.lower() == "bye":

                        print("Client has exited.")

                        break

                    message = aes_decrypt(encrypted_message, aes_key)

                    print(f"Client: {message}")

                    response = input("You (Server): ")

                    if response.lower() == "bye":

                        encrypted_message = aes_encrypt("bye", aes_key)

                        encoded_message = encrypted_message.encode('utf-8')

                        client_socket.send(encoded_message)



                        print("You have exited the chat.")

                        break

                    encrypted_response = aes_encrypt(response, aes_key)

                    encoded_response = encrypted_response.encode('utf-8')

                    client_socket.send(encoded_response)



            break

        else:

            break

    

    client_socket.close()



def main():

    print("\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n")



    # Create the server socket

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('localhost', 8080)

    server_socket.bind(server_address)

    server_socket.listen(5)



    while True:

        client_socket, client_address = server_socket.accept()



        pid = os.fork()

        if pid == -1:

            print("Error! Unable to fork process.")

        elif pid == 0:

            handle_client(client_socket)

            os._exit(0)

        else:

            client_socket.close()



if __name__ == "__main__":

    main()