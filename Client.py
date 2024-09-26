import ast
import base64
import json
import os
import socket

import rsa
from dotenv import load_dotenv

from json_keys import JsonKeys as jk

# env
load_dotenv()


class REVClient:
    def __init__(self, firstname: str, lastname: str, password: str):
        self.socket = socket.create_connection((os.getenv("HOST"), int(os.getenv("PORT"))), timeout=180)

        self.firstname = firstname
        self.lastname = lastname
        self.password = password
        self.id = None
        self.iden_num_len = None

        self.client_private_key = None
        self.client_public_key = None
        self.server_public_key = None
        self.server_pubkey_n = None
        self.server_pubkey_e = None
        self.client_pubkey_n = None
        self.client_pubkey_e = None
        self.client_privkey_d = None

        self.generate_rsa_keys()

    def run(self):
        self.rsa_key_exchange()

        print(self.registration_handler())

        print(self.authentication_handler())

        self.get_crypt_params()

        self.socket.close()

    def generate_rsa_keys(self) -> None:
        self.client_public_key, self.client_private_key = rsa.newkeys(512)

        self.client_pubkey_n = self.client_public_key.n
        self.client_pubkey_e = self.client_public_key.e
        self.client_privkey_d = self.client_private_key.d

    def rsa_key_exchange(self) -> None:
        send_data = {jk.REQUEST: jk.KEY_EXCHANGE,
                     jk.KEYEX_CLIENT_PUB_N: str(self.client_pubkey_n),
                     jk.KEYEX_CLIENT_PUB_E: str(self.client_pubkey_e)}
        self.send_json(send_data)

        recv_data = self.recv_json()
        self.server_pubkey_n = int(recv_data[jk.KEYEX_SERVER_PUB_N])
        self.server_pubkey_e = int(recv_data[jk.KEYEX_SERVER_PUB_E])
        self.server_public_key = rsa.PublicKey(self.server_pubkey_n,
                                               self.server_pubkey_e)

    def registration_handler(self) -> bool:
        self.send_json(self.json_encrypt({jk.REQUEST: jk.REGISTRATION,
                                          jk.FIRSTNAME: self.firstname,
                                          jk.LASTNAME: self.lastname,
                                          jk.PASSWORD: self.password}))
        reg_data = self.json_decrypt(self.recv_json())
        return True if reg_data[jk.REG_STATE] in ["Successful", "Voter exists"] else False

    def authentication_handler(self) -> bool:
        self.send_json(self.json_encrypt({jk.REQUEST: jk.AUTENTICATION,
                                          jk.FIRSTNAME: self.firstname,
                                          jk.LASTNAME: self.lastname,
                                          jk.PASSWORD: self.password}))
        auth_data = self.json_decrypt(self.recv_json())
        return ast.literal_eval(auth_data[jk.AUTH_STATE])

    def get_crypt_params(self) -> None:
        self.send_json({jk.REQUEST: jk.CRYPT_STAGE_1_INIT,
                        jk.FIRSTNAME: self.firstname,
                        jk.LASTNAME: self.lastname})
        crypt_stage_1_data = self.recv_json()

        self.id = crypt_stage_1_data[jk.VOTER_ID]
        self.iden_num_len = crypt_stage_1_data[jk.IDEN_NUM_LEN]

    def json_encrypt(self, json_data: dict[str: str]) -> dict[str: str]:
        encrypt_dict = {}
        for item in json_data:
            if item == jk.PASSWORD:
                encrypt = rsa.encrypt(str(json_data[item]).encode(), self.server_public_key)
                encrypt_dict[item] = base64.b64encode(encrypt).decode()
            else:
                encrypt_dict[item] = json_data[item]
        return encrypt_dict

    def json_decrypt(self, encrypt_json: dict[str: str]) -> dict[str: str]:
        json_data = {}
        for item in encrypt_json:
            if item == jk.PASSWORD:
                decode = base64.b64decode(encrypt_json[item])
                json_data[item] = rsa.decrypt(decode, self.client_private_key).decode()
            else:
                json_data[item] = encrypt_json[item]
        return json_data

    def send_json(self, message: dict[str: str]):
        json_data = json.dumps(message)
        self.socket.send(json_data.encode())

    def recv_json(self):
        return json.loads(self.socket.recv(16384).decode())

    def __del__(self):
        self.socket.close()
