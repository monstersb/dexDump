#! /usr/bin/env python
#! -*- coding:utf-8 -*-

from utils import hexDump, bytes2int

class DexFileHeader(object):
    def __init__(self, data):
        self.magic = data[0x00:0x08]
        self.checksum = data[0x08:0x0C]
        self.signature = data[0x0C:0x20]
        self.file_size = data[0x20:0x24]
        self.header_size = data[0x24:0x28]
        self.endian_tag = data[0x28:0x2C]
        self.link_size = data[0x2C:0x30]
        self.link_off = data[0x30:0x34]
        self.map_off = data[0x34:0x38]
        self.string_ids_size = data[0x38:0x3C]
        self.string_ids_off = data[0x3C:0x40]
        self.type_ids_size = data[0x40:0x44]
        self.type_ids_off = data[0x44:0x48]
        self.proto_ids_size = data[0x48:0x4C]
        self.proto_ids_off = data[0x4C:0x50]
        self.field_ids_size = data[0x50:0x54]
        self.field_ids_off = data[0x54:0x58]
        self.method_ids_size = data[0x58:0x5C]
        self.method_ids_off = data[0x5C:0x60]
        self.class_defs_size = data[0x60:0x64]
        self.class_defs_off = data[0x64:0x68]
        self.data_size = data[0x68:0x6C]
        self.data_off = data[0x6C:0x70]

    def show(self):
        print ' {0:<20}{1}'.format('magic', hexDump(self.magic))
        print ' {0:<20}{1}'.format('checksum', hexDump(self.checksum))
        print ' {0:<20}{1}'.format('signature', hexDump(self.signature))
        print ' {0:<20}{1:0>8X}'.format('file_size', bytes2int(self.file_size))
        print ' {0:<20}{1:0>8X}'.format('header_size', bytes2int(self.header_size))
        print ' {0:<20}{1}'.format('endian_tag', hexDump(self.endian_tag))
        print ' {0:<20}{1:0>8X}'.format('link_size', bytes2int(self.link_size))
        print ' {0:<20}{1:0>8X}'.format('link_off', bytes2int(self.link_off))
        print ' {0:<20}{1:0>8X}'.format('map_off', bytes2int(self.map_off))
        print ' {0:<20}{1:0>8X}'.format('string_ids_size', bytes2int(self.string_ids_size))
        print ' {0:<20}{1:0>8X}'.format('string_ids_off', bytes2int(self.string_ids_off))
        print ' {0:<20}{1:0>8X}'.format('type_ids_size', bytes2int(self.type_ids_size))
        print ' {0:<20}{1:0>8X}'.format('type_ids_off', bytes2int(self.type_ids_off))
        print ' {0:<20}{1:0>8X}'.format('proto_ids_size', bytes2int(self.proto_ids_size))
        print ' {0:<20}{1:0>8X}'.format('proto_ids_off', bytes2int(self.proto_ids_off))
        print ' {0:<20}{1:0>8X}'.format('field_ids_size', bytes2int(self.field_ids_size))
        print ' {0:<20}{1:0>8X}'.format('field_ids_off', bytes2int(self.field_ids_off))
        print ' {0:<20}{1:0>8X}'.format('method_ids_size', bytes2int(self.method_ids_size))
        print ' {0:<20}{1:0>8X}'.format('method_ids_off', bytes2int(self.method_ids_off))
        print ' {0:<20}{1:0>8X}'.format('class_defs_size', bytes2int(self.class_defs_size))
        print ' {0:<20}{1:0>8X}'.format('class_defs_off', bytes2int(self.class_defs_off))
        print ' {0:<20}{1:0>8X}'.format('data_size', bytes2int(self.data_size))
        print ' {0:<20}{1:0>8X}'.format('data_off', bytes2int(self.data_off))
