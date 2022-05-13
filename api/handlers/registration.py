import os
from des import DesKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .utils import hashPassword
from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip() 
            if not isinstance(email, str):
                raise Exception()

            password = body['password']
            hashed_password = hashPassword(password)

            if not isinstance(password, str):
                raise Exception()

            disabilities = body.get('disabilities')
            if disabilities is None:
                disabilities = ""

            disabilities_bytes = bytes(disabilities, "utf-8")
            disabilities_cipher_bytes = self.key.encrypt(disabilities_bytes, padding=True)
            disabilities_ciphertext = disabilities_cipher_bytes.hex()
            print("disabilities_ciphertext: " + disabilities_ciphertext)

            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            print(repr(e))
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'displayName': display_name,
            'disabilities':disabilities_ciphertext
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()