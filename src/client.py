import socket

import hashlib

import random

from Crypto.Cipher import AES

from Crypto.Util.Padding import pad, unpad

import base64



P = 23

G = 5 



def create_socket():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('localhost', 8080)

    sock.connect(server_address)

    return sock



def diffie_hellman_exchange(sock):

    # generating client private and public key

    client_private = random.randint(1000, 9999)

    client_public = pow(G, client_private, P)

    

    # send client public key to the server

    client_public_str = str(client_public)

    encoded_client_public = client_public_str.encode('utf-8')

    sock.send(encoded_client_public)



    # receive server public key

    data = sock.recv(1024)

    decoded_data = data.decode('utf-8')

    server_public = int(decoded_data)



    # calculatng the shared secret key

    shared_key = pow(server_public, client_private, P)

    

    # convert shared key to bytes and pad to 16 bytes for aes

    shared_key_str = str(shared_key)

    encoded_shared_key = shared_key_str.encode()

    hashed_shared_key = hashlib.sha256(encoded_shared_key).digest()

    aes_key = hashed_shared_key[:16]



    return aes_key



def aes_encrypt(message, key):

    cipher = AES.new(key, AES.MODE_CBC)

    message_bytes = message.encode('utf-8')

    padded_message = pad(message_bytes, AES.block_size)

    ciphertext = cipher.encrypt(padded_message)

    encoded_ciphertext = base64.b64encode(cipher.iv + ciphertext)

    return encoded_ciphertext.decode('utf-8')



def aes_decrypt(ciphertext, key):

    decoded_ciphertext = base64.b64decode(ciphertext)  # decoded back to original byte format from base64

    iv = decoded_ciphertext[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted_message = decoded_ciphertext[16:]

    decrypted_message = cipher.decrypt(encrypted_message)

    plaintext = unpad(decrypted_message, AES.block_size)

    return plaintext.decode('utf-8')



def main():

    print("\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n")

    

    # creating socket and connecting to the server

    sock = create_socket()



    while True:

        print("1. Register")

        print("2. Login")

        option = input("Choose an option: ")

        byte = option.encode('utf-8')

        sock.send(byte)  # it will send the chosen option to the server



        if option == '1':

            # for registration

            email = input("Enter email: ")

            username = input("Enter username: ")

            password = input("Enter password: ")

            msg = (f"{email},{username},{password}")

            encoded_msg = msg.encode('utf-8')

            sock.send(encoded_msg)

            

            response = sock.recv(1024)

            decoded_response = response.decode('utf-8')

            print(decoded_response)  # receive and print server's response

            

        elif option == '2':

            # for login

            username = input("Enter username: ")

            password = input("Enter password: ")

            msg = f"{username},{password}"

            encoded_msg = msg.encode('utf-8')

            sock.send(encoded_msg)

            

            response = sock.recv(1024)

            decoded_response = response.decode('utf-8')

            print(decoded_response)

            if "successful" in decoded_response:

                aes_key = diffie_hellman_exchange(sock)



                # enter chat loop

                while True:

                    #send encrypted message to the server

                    message = input("You (Client): ")

                    if message.lower() == "bye":

                        encrypted_message = aes_encrypt("bye", aes_key)

                        encoded_message = encrypted_message.encode('utf-8')

                        sock.send(encoded_message)

                        print("You have exited the chat.")

                        break

                    encrypted_message = aes_encrypt(message, aes_key)

                    encoded_message = encrypted_message.encode('utf-8')

                    sock.send(encoded_message)



                    #receive and decrypt message from the server

                    encrypted_response = sock.recv(1024)

                    decoded_response = encrypted_response.decode('utf-8')



                    if decoded_response.lower() == "bye":

                        print("Server has exited the chat.")

                        break

                    response = aes_decrypt(decoded_response, aes_key)

                    print(f"Server: {response}")

            break

        else:

            print("Invalid option, please try again.")



    sock.close()



if __name__ == "__main__":

    main()