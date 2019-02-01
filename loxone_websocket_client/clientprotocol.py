#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging

from autobahn.asyncio.websocket import WebSocketClientProtocol

from time import sleep

from .textmessage import TextMessage
from .messageheader import MessageHeader
from .valuestate import ValueState
from .textstate import TextState
from .miniserver import MiniServer
from .token import Token
from .tokenenc import TokenEnc
from .loxprotocol import LoxProtocol

_LOGGER = logging.getLogger(__name__)


class ClientProtocol(LoxProtocol):

    def onMessage(self, payload, isBinary):

        if isBinary:

            _LOGGER.debug('Binary message received: {0} bytes'.format(len(payload)))

            if payload.startswith(b'\x03'):
                # It's a header in this case.
                _LOGGER.debug('Message Header received.')
                self.next_msg_header = MessageHeader(payload)
                _LOGGER.debug('Next Message will have Identifier: {0} and Payload length: {1} bytes'
                    .format(self.next_msg_header.identifier, self.next_msg_header.payload_length))

                if self.next_msg_header.identifier == 2:
                    _LOGGER.debug('Next Message will be Event-Table of Value-States')
                if self.next_msg_header.identifier == 3:
                    _LOGGER.debug('Next Message will be Event-Table of Text-States')


            # for Event-Table of Value-States
            if self.next_msg_header.identifier == 2 and not payload.startswith(b'\x03'):
                _LOGGER.debug('Extracting {0} states from table.'.format(int(len(payload)/24)+1))
                offset = 0
                for n in range(int(len(payload)/24)):
                    event_table = ValueState(payload[offset:offset+24])
                    _LOGGER.debug('Value-State {2}: uuid: {0} value: {1}'.format(
                        event_table.getUuid(), event_table.getValue(), n+1))
                    offset = offset+24

            # for Event-Table of Text-States
            if self.next_msg_header.identifier == 3 and not payload.startswith(b'\x03'):
                _LOGGER.debug("Event Table of Text States received, but no handler implemented.")
                '''_LOGGER.debug('Extracting text states from table')
                offset = 0
                _LOGGER.debug(payload)
                event_table = TextState(payload)
                _LOGGER.debug('Text-State: uuid: {0} text-length: {1} content:'.format(
                    event_table.getUuid(), event_table.getTextLength(), event_table.text))'''

            # for Event-Table of Daytimer-States
            if self.next_msg_header.identifier == 4:
                _LOGGER.debug("Event-Table of Daytimer-States received, but no handler implemented.")
            
            # for Out-Of-Service Indicator 
            if self.next_msg_header.identifier == 5:
                _LOGGER.debug("Out-Of-Service Indicator received, but no handler implemented.")

            # for keepalive response
            if self.next_msg_header.identifier == 6:
                _LOGGER.debug("keepalive response received, but no handler implemented.")

            # for Event-Table of Weather-States
            if self.next_msg_header.identifier == 7:
                _LOGGER.debug("Event-Table of Weather-States received, but no handler implemented.")
        
        else:
            
            _LOGGER.debug('Text message received: {0}'.format(payload.decode('utf8')))
            
            if self.next_msg_header.payload_length == len(payload):
                msg = TextMessage(payload)
                _LOGGER.debug('Code: {0}'.format(msg.code))
                _LOGGER.debug('Control: {0}'.format(msg.control))
                _LOGGER.debug('Control type: {0}'.format(msg.control_type))
                _LOGGER.debug('Value: {0}'.format(msg.value))
                
                if msg.control_type == 'enc':
                    _LOGGER.info('Encrypted command received')
                    msg.control = self.token_enc.decrypt_command(msg.control)
                
                if msg.control_type == 'auth' and msg.code == 420:
                    _LOGGER.info('Authentication failed (status code {0})'.format(msg.code))
                
                if msg.control_type == 'keyexchange' and msg.code == 200:
                    _LOGGER.info('Keyexchange succeeded')
                
                if msg.control_type == 'keyexchange' and msg.code != 200:
                    _LOGGER.info('Keyexchange failed (status code {0})'.format(msg.code))
                
                if msg.control_type == 'getkey2' and msg.code == 200:
                    _LOGGER.info('Salt and key received for user')
                    self.token_enc.miniserver_user_key = msg.value.get('key')
                    self.token_enc.miniserver_user_salt = msg.value.get('salt')
                    self.sendMessage(self.token_enc.encrypt_command(self.token_enc.get_token()))
                
                if msg.control_type == 'getkey2' and msg.code != 200:
                    _LOGGER.info('Salt and key not received for user (status code {0})'.format(msg.code))
                    # TODO retry after 401 error?

                
                if msg.control_type == 'gettoken' and msg.code == 200:
                    _LOGGER.info('Token received')
                    self.token_enc.client_token = Token(msg.value)
                    self.factory.loop.create_task(self.refresh_token_periodical(self.token_enc.client_token.seconds_to_expire()))
                    self.sendMessage(self.token_enc.get_loxapp3_json())
                    self.sendMessage(self.token_enc.enable_state_updates())
                
                if msg.control_type == 'gettoken' and msg.code != 200:
                    _LOGGER.info('Token not received (status code {0})'.format(msg.code))
                
                if msg.control_type == 'getkey' and msg.code == 200:
                    _LOGGER.info('Key received')
                    self.token_enc.client_token.key = msg.value
                    self.sendMessage(self.token_enc.encrypt_command(self.token_enc.refresh_token()))
                
                if msg.control_type == 'getkey' and msg.code != 200:
                    _LOGGER.info('Key not received (status code {0})'.format(msg.code))
                
                if msg.control_type == 'refreshtoken' and msg.code == 200:
                    _LOGGER.info('Token refreshed')
                    self.token_enc.client_token.refresh(msg.value)
                
                if msg.control_type == 'refreshtoken' and msg.code != 200:
                    _LOGGER.info('Token not refreshed (status code {0})'.format(msg.code))
                
                if msg.control_type == 'loxapp3' and msg.code == 0:
                    _LOGGER.info('LoxAPP3.json received')
                
                if msg.control_type == 'enablebinstatusupdate':
                    _LOGGER.debug("ok, prepared for some updates!")
                    _LOGGER.debug('{0}'.format(msg.data))
                
                if msg.control_type == 'unknown':
                    _LOGGER.info('Unknown control "{0}" with value "{1}" (status code {2})'.format(msg.control, msg.value, msg.code))
            
            else:
                _LOGGER.error('ERROR: Promised length of payload does not match')

    def onClose(self, wasClean, code, reason):
        _LOGGER.info('WebSocket connection closed: {0}'.format(reason))
