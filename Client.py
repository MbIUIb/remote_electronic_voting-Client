import json
import os
import socket

from dotenv import load_dotenv


class REVClient:
    def __init__(self):
        # env
        load_dotenv()
        self.socket = socket.create_connection((os.getenv("HOST"), int(os.getenv("PORT"))))

    def run(self):
        registration_stmt = {"request": "registration",
                             "firstname": "mbiuib1",
                             "lastname": "mbiuib",
                             "password": "mbiuib123"}
        self.send_json(registration_stmt)
        reg_data = self.recv_json()

        authentication_stmt = {"request": "authentication",
                               "firstname": "mbiuib1",
                               "lastname": "mbiuib",
                               "password": "mbiuib123"}
        self.send_json(authentication_stmt)
        auth_data = self.recv_json()

        self.socket.send("stage_1 data".encode())

    def send_json(self, message: dict[str: str]):
        json_data = json.dumps(message)
        self.socket.send(json_data.encode())

    def recv_json(self):
        return self.socket.recv(1024).decode()

    def __del__(self):
        self.socket.close()
