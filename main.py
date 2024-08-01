import socket

HOST = 'localhost'
PORT = 9999

socket = socket.create_connection((HOST, PORT))

msg = "hello world123!!!"
socket.send(msg.encode())

data = socket.recv(1024)
print(data.decode())
socket.close()
