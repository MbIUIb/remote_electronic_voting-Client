import base64
import json
import os
import socket

import rsa
from dotenv import load_dotenv

# env
load_dotenv()


class REVClient:
    def __init__(self):
        self.socket = socket.create_connection((os.getenv("HOST"), int(os.getenv("PORT"))), timeout=180)
        self.client_private_key = None
        self.client_public_key = None
        self.server_pubkey_n = None
        self.server_pubkey_e = None
        self.client_pubkey_n = None
        self.client_pubkey_e = None
        self.client_privkey_d = None

        self.generate_rsa_keys()

    def run(self):
        self.rsa_key_exchange()

        registration_stmt = {"request": "registration",
                             "firstname": "mbiuib3",
                             "lastname": "mbiuib",
                             "password": "mbiuib123"}
        self.send_json(self.json_encrypt(registration_stmt))
        reg_data = json.loads(self.recv_json())
        print(self.json_decrypt(reg_data))

        authentication_stmt = {"request": "authentication",
                               "firstname": "mbiuib3",
                               "lastname": "mbiuib",
                               "password": "mbiuib123"}
        self.send_json(self.json_encrypt(authentication_stmt))
        auth_data = json.loads(self.recv_json())
        print(self.json_decrypt(auth_data))

        self.socket.send("stage_1 data".encode())

    def generate_rsa_keys(self):
        self.client_public_key, self.client_private_key = rsa.newkeys(512)

        self.client_pubkey_n = self.client_public_key.n
        self.client_pubkey_e = self.client_public_key.e
        self.client_privkey_d = self.client_private_key.d

    def rsa_key_exchange(self):
        self.socket.send(str(self.client_pubkey_n).encode())
        self.socket.send(str(self.client_pubkey_e).encode())

        self.server_pubkey_n = int(self.socket.recv(4096).decode())
        self.server_pubkey_e = int(self.socket.recv(4096).decode())

    def json_encrypt(self, json_data: dict[str: str]) -> dict[str: str]:
        encrypt_dict = {}
        for item in json_data:
            encrypt = rsa.encrypt(str(json_data[item]).encode(),
                                  rsa.PublicKey(self.server_pubkey_n,
                                                self.server_pubkey_e))
            encrypt_dict[item] = base64.b64encode(encrypt).decode()
        return encrypt_dict

    def json_decrypt(self, encrypt_json: dict[str: str]) -> dict[str: str]:
        json_data = {}
        for item in encrypt_json:
            decode = base64.b64decode(encrypt_json[item])
            json_data[item] = rsa.decrypt(decode, self.client_private_key).decode()
        return json_data

    def send_json(self, message: dict[str: str]):
        json_data = json.dumps(message)
        self.socket.send(json_data.encode())

    def recv_json(self):
        return self.socket.recv(16384).decode()

    def __del__(self):
        self.socket.close()
