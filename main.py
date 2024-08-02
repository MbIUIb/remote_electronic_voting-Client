import json
import socket

HOST = 'localhost'
PORT = 9999

socket = socket.create_connection((HOST, PORT))

registration_stmt = {"request": "registration",
                     "firstname": "mbiuib1",
                     "lastname": "mbiuib",
                     "password": "mbiuib123"}
json_data = json.dumps(registration_stmt)
socket.send(json_data.encode())

data = socket.recv(1024)
print(data.decode())


authentication_stmt = {"request": "authentication",
                       "firstname": "mbiuib1",
                       "lastname": "mbiuib",
                       "password": "mbiuib123"}
json_data = json.dumps(authentication_stmt)
socket.send(json_data.encode())

data = socket.recv(1024)
print(data.decode())

socket.send("data".encode())

socket.close()
