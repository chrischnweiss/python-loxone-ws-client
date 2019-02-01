#!/usr/bin/env python
# -*- coding: utf-8 -*-

from struct import unpack


class Uuid:

    def __init__(self, payload):
        """
        typedef struct _UUID {
            unsigned long Data1; // 32-Bit Unsigned Integer (little endian)
            unsigned short Data2; // 16-Bit Unsigned Integer (little endian)
            unsigned short Data3; // 16-Bit Unsigned Integer (little endian)
            unsigned char Data4 [8]; // 8-Bit Uint8Array [8] (little endian)
        } PACKED PUUID;

        example: 1086193a-0199-51b1-ffff86fcc6939c61
        """
        self.raw_uuid = unpack('<LHH8B', payload)
        self.formatted_uuid = "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x" % (
            self.raw_uuid[0],
            self.raw_uuid[1],
            self.raw_uuid[2],
            self.raw_uuid[3],
            self.raw_uuid[4],
            self.raw_uuid[5],
            self.raw_uuid[6],
            self.raw_uuid[7],
            self.raw_uuid[8],
            self.raw_uuid[9],
            self.raw_uuid[10]
        )

    def get(self):
        return self.formatted_uuid