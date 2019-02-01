#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
from base64 import b64decode, b64encode
from binascii import a2b_hex
from datetime import datetime, timedelta
from re import sub

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1
from Crypto.Util.py3compat import bchr
from requests import codes, get, utils

_LOGGER = logging.getLogger(__name__)


class TokenEnc:

    def __init__(self):
        self.miniserver = None
        self.miniserver_user_key = None
        self.miniserver_user_salt = None
        self.client_aes_key = self.generate_aes256_key()
        self.client_aes_iv = self.generate_aes_iv()
        self.client_session_key = None
        self.client_salt = None
        self.client_salt_valid_until = None
        self.client_salt_usage_count = 0
        self.client_salt_usage_max = 20
        self.client_token = None

        self.generate_salt()

    def generate_aes256_key(self):
        _LOGGER.info('Generate AES-256 key')
        secret = Random.get_random_bytes(32)
        key = Random.get_random_bytes(32)
        iv = Random.new().read(AES.block_size)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        return cipher_aes.encrypt(secret)

    def generate_aes_iv(self):
        _LOGGER.info('Generate random AES IV (16 byte)')
        return Random.get_random_bytes(16)

    def generate_session_key(self):
        _LOGGER.info('Generate session key')
        cipher_rsa = PKCS1_v1_5.new(self.miniserver.public_key)
        session_key = self.client_aes_key+b':'+self.client_aes_iv
        enc_session_key = cipher_rsa.encrypt(session_key)
        self.client_session_key = b64encode(enc_session_key)
        return self.client_session_key

    def generate_salt(self):
        _LOGGER.info('Generate salt')
        self.client_salt_valid_until = datetime.now() + timedelta(hours=1)
        self.client_salt_usage_count = 0
        self.client_salt = Random.get_random_bytes(16).hex()
        return self.client_salt

    def new_salt_needed(self):
        _LOGGER.info('New salt needed?')
        if datetime.now() >= self.client_salt_valid_until:
            _LOGGER.info('Salt validity time reached. New salt needed.')
            return True
        elif self.client_salt_usage_count >= self.client_salt_usage_max:
            _LOGGER.info('Salt max usage count reached. New salt needed.')
            return True
        else:
            _LOGGER.info('Salt okay. Current salt used.')
            return False

    def exchange_session_key(self):
        _LOGGER.info('Exchange session key')
        return b'jdev/sys/keyexchange/'+self.client_session_key

    @staticmethod
    def zero_byte_paddding(data_to_pad, block_size):
        padding_len = block_size-len(data_to_pad) % block_size
        padding = bchr(0)*padding_len
        return data_to_pad + padding

    def encrypt_command(self, cmd):
        _LOGGER.info('Encrypt command')
        if type(cmd) != str:
            raise TypeError(
                'Wrong type for "cmd" paramater. Expect Str got {0}.'.format(type(cmd)))

        salt_part = 'salt/{0}'.format(self.client_salt)
        self.client_salt_usage_count += 1
        if self.new_salt_needed() == True:
            salt_part = 'nextSalt/{0}/'.format(self.client_salt)
            self.generate_salt()
            salt_part += self.client_salt

        cipher_aes = AES.new(self.client_aes_key,
                             AES.MODE_CBC,
                             self.client_aes_iv)
        enc_cmd_part = cipher_aes.encrypt(self.zero_byte_paddding(
            '{0}/{1}'.format(salt_part, cmd).encode('utf8'), AES.block_size))
        enc_cmd = 'jdev/sys/enc/{0}'.format(
            utils.quote(b64encode(enc_cmd_part))).encode('utf8')
        return enc_cmd

    def get_key_and_salt(self):
        _LOGGER.info('Get key and salt for user')
        return 'jdev/sys/getkey2/{0}'.format(self.miniserver.username)

    def hash_password(self):
        _LOGGER.info('Hash user password')
        hash_sha = SHA1.new()
        hash_sha.update('{0}:{1}'.format(
            self.miniserver.password,
            self.miniserver_user_salt).encode('utf8'))
        return hash_sha.hexdigest().upper()

    def hash_credential(self):
        _LOGGER.info('Hash credential')
        pw_hash = self.hash_password()
        hash_hmac = HMAC.new(a2b_hex(self.miniserver_user_key), digestmod=SHA1)
        hash_hmac.update('{0}:{1}'.format(
            self.miniserver.username,
            pw_hash).encode('utf8'))
        return hash_hmac.hexdigest()

    def get_token(self):
        _LOGGER.info('Get token')
        credential_hash = self.hash_credential()
        permission = 2
        uuid = 'd8432922-c1ce-480a-8a01669ef2c02c20'
        info = 'python-loxone-ws-client'
        return 'jdev/sys/gettoken/{0}/{1}/{2}/{3}/{4}'.format(
            credential_hash,
            self.miniserver.username,
            permission,
            uuid,
            utils.quote(info))

    @staticmethod
    def zero_byte_unpadding(padded_data, block_size):
        pdata_len = len(padded_data)
        if pdata_len % block_size:
            raise ValueError("Input data is not padded")
        return sub(b'\x00+$', b'', padded_data)

    def decrypt_command(self, cmd):
        _LOGGER.info('Decrypt command')
        if type(cmd) != str:
            raise TypeError(
                'Wrong type for "cmd" paramater. Expect Str got {0}.'.format(type(cmd)))

        enc_cmd_part = b64decode(utils.unquote(cmd[13:]).encode('utf8'))
        cipher_aes = AES.new(self.client_aes_key,
                             AES.MODE_CBC,
                             self.client_aes_iv)
        return self.zero_byte_unpadding(cipher_aes.decrypt(enc_cmd_part), AES.block_size).decode('utf8')

    def get_key(self):
        _LOGGER.info('Get key')
        return 'jdev/sys/getkey'

    def hash_token(self):
        _LOGGER.info('Hash token')
        hash_hmac = HMAC.new(self.client_token.key, digestmod=SHA1)
        hash_hmac.update(self.client_token.value)
        return hash_hmac.hexdigest()

    def refresh_token(self):
        _LOGGER.info('Refresh token')
        token_hash = self.hash_token()
        return 'jdev/sys/refreshtoken/{0}/{1}'.format(token_hash, self.miniserver.username)

    def get_loxapp3_json(self):
        _LOGGER.info('Get LoxAPP3.json')
        # Command can't be encrypted
        return 'data/LoxAPP3.json'.encode('utf8')

    def enable_state_updates(self):
        _LOGGER.info("Enable state-updates.")
        return 'jdev/sps/enablebinstatusupdate'.encode('utf8')