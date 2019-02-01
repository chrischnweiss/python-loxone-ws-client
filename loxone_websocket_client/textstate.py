#!/usr/bin/env python
# -*- coding: utf-8 -*-

from struct import unpack

from .uuid import Uuid


class TextState:

    def __init__(self, payload):
        """
        typedef struct { // starts at multiple of 4
            PUUID uuid; // 128-Bit uuid
            PUUID uuidIcon; // 128-Bit uuid of icon
            unsigned long textLength; // 32-Bit Unsigned Integer (little endian)
            // text follows here
        } PACKED EvDataText;
        """
        self.uuid = Uuid(payload[0:16])
        self.uuidIcon = Uuid(payload[17:33])
        self.textLength = unpack('<L', payload[34:38])
        self.text = payload[39:int(self.textLength[0]/4)]

    def getUuid(self):
        return self.uuid.get()

    def getTextLength(self):
        return self.textLength[0]

    def getText(self):
        return self.value[0]