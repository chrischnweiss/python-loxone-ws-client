#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging

from autobahn.asyncio.websocket import WebSocketClientProtocol

from time import sleep

from .message import Message
from .messageheader import MessageHeader
from .valuestate import ValueState
from .textstate import TextState
from .miniserver import MiniServer
from .token import Token
from .tokenenc import TokenEnc

_LOGGER = logging.getLogger(__name__)


class LoxProtocol(WebSocketClientProtocol):

    next_msg_header = None
    token_enc = None

    async def refresh_token_periodical(self, interval):
        while True:
            await asyncio.sleep(interval)
            self.sendMessage(self.token_enc.encrypt_command(self.token_enc.get_key()))

    def onConnect(self, response):
        _LOGGER.info('Server connected: {0}'.format(response.peer))
        _LOGGER.debug(response)
        self.token_enc = TokenEnc()

    def onOpen(self):
        _LOGGER.info('WebSocket connection open')

        self.token_enc.miniserver = MiniServer(
            self.factory.host,
            self.factory.port,
            self.factory.username,
            self.factory.password)
        _LOGGER.info('MiniServer serial number: {0}'.format(
            self.token_enc.miniserver.snr))
        _LOGGER.info('MiniServer version: {0}'.format(
            self.token_enc.miniserver.version))

        self.token_enc.generate_session_key()

        self.sendMessage(self.token_enc.exchange_session_key())
        self.sendMessage(self.token_enc.encrypt_command(self.token_enc.get_key_and_salt()))

    def onClose(self, wasClean, code, reason):
        _LOGGER.info('WebSocket connection closed: {0}'.format(reason))

    def onMessage(self, payload, isBinary):
        if isBinary:
            _LOGGER.debug('Binary message received: {0} bytes'.format(len(payload)))
        else:
            _LOGGER.debug('Text message received: {0}'.format(payload.decode('utf8')))




