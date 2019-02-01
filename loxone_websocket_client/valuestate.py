#!/usr/bin/env python
# -*- coding: utf-8 -*-

from struct import unpack

from .uuid import Uuid


class ValueState:

    def __init__(self, payload):
        """
        typedef struct {
​           PUUID uuid; // 128-Bit uuid
​           double dVal; // 64-Bit Float (little endian) value
        } PACKED EvData;
        """
        self.uuid = Uuid(payload[0:16])
        if len(payload) == 24:
            self.value = unpack('<d', payload[-8:])

    def getUuid(self):
        return self.uuid.get()

    def getValue(self):
        return self.value[0]