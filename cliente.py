#! /usr/bin/python3
# coding=utf-8

import socket
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decode_base64(received_base64_message):
    """
    Function to decode a message in Base64 
    """
    base64_bytes = received_base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes) 
    decoded_plaintext_message = message_bytes.decode('ascii')
    return decoded_plaintext_message

def cifrado(comando, llave_privada):
    '''
    Cifrar el comando
    param: salida_comando String to be encrypted
    param: llave_publica public key
    return base64 encoded encrypted string
    '''
    
    rsakey = RSA.importKey(llave_privada)
    rsakey = PKCS1_OAEP.new(rsakey)
    comando_bytes = comando.encode("utf-8") #comando debe estar en bytes
    encrypted = rsakey.encrypt(comando_bytes)
    print ("encrypted :")
    return encrypted

def descifrado(salida_comando_cifrado_pub, llave_privada):
    """
    Decifrar el comando
    param: command_cifrado_priv String to be decrypted
    param: llave_publica public key
    return decrypted string
    """

    rsakey = RSA.importKey(llave_privada) 
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(salida_comando_cifrado_pub)) 
    return decrypted

 
HOST = "127.0.0.1"
PORT = 44444

#leer llave
llave_privada = open("id_rsa", "r").read()

while True:
    #data = str.encode(input(">>: "))
    data = cifrado(input(">>: "),llave_privada)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
        new_socket.connect((HOST, PORT))
        new_socket.sendall(data)
        data = new_socket.recv(1024)
        data = data.decode() #para que se vea mejor
        #data = decode_base64(data)
        data = descifrado(data,llave_privada) #decifrar con llave privada
        print(f"Received data: \n{data}")
