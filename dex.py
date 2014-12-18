#! /usr/bin/env python
#! -*- coding:utf-8 -*-

from utils import *
from constant import *

class DexFile(object):
    def __init__(self, data):
        self.buffer = data[:]
        self.fileHeader = DexFileHeader(self)
        self.mapList = MapList(data[self.fileHeader.map_off:], self)
        self.stringIDs = StringIDs(data, self)

    def show(self):
        self.fileHeader.show()
        self.mapList.show()
        self.stringIDs.show()

class DexFileHeader(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.data = dex.buffer
        self.magic = self.data[0x00:0x08]
        self.checksum = self.data[0x08:0x0C]
        self.signature = self.data[0x0C:0x20]
        self.file_size = bytes2int(self.data[0x20:0x24])
        self.header_size = bytes2int(self.data[0x24:0x28])
        self.endian_tag = self.data[0x28:0x2C]
        self.link_size = self.data[0x2C:0x30]
        self.link_off = self.data[0x30:0x34]
        self.map_off = bytes2int(self.data[0x34:0x38])
        self.string_ids_size = bytes2int(self.data[0x38:0x3C])
        self.string_ids_off = bytes2int(self.data[0x3C:0x40])
        self.type_ids_size = self.data[0x40:0x44]
        self.type_ids_off = self.data[0x44:0x48]
        self.proto_ids_size = self.data[0x48:0x4C]
        self.proto_ids_off = self.data[0x4C:0x50]
        self.field_ids_size = self.data[0x50:0x54]
        self.field_ids_off = self.data[0x54:0x58]
        self.method_ids_size = self.data[0x58:0x5C]
        self.method_ids_off = self.data[0x5C:0x60]
        self.class_defs_size = self.data[0x60:0x64]
        self.class_defs_off = self.data[0x64:0x68]
        self.data_size = self.data[0x68:0x6C]
        self.data_off = self.data[0x6C:0x70]

    def show(self, align = ''):
        print '{0}Dex file header:'.format(align)
        print '  {0}{1:18}{2}'.format(align, 'magic', hexDump(self.magic))
        print '  {0}{1:18}{2}'.format(align, 'checksum', hexDump(self.checksum))
        print '  {0}{1:18}{2}'.format(align, 'signature', hexDump(self.signature))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'file_size', self.file_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'header_size', self.header_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'endian_tag', bytes2int(self.endian_tag))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'link_size', bytes2int(self.link_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'link_off', bytes2int(self.link_off))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'map_off', self.map_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'string_ids_size', self.string_ids_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'string_ids_off', self.string_ids_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'type_ids_size', bytes2int(self.type_ids_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'type_ids_off', bytes2int(self.type_ids_off))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'proto_ids_size', bytes2int(self.proto_ids_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'proto_ids_off', bytes2int(self.proto_ids_off))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'field_ids_size', bytes2int(self.field_ids_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'field_ids_off', bytes2int(self.field_ids_off))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'method_ids_size', bytes2int(self.method_ids_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'method_ids_off', bytes2int(self.method_ids_off))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'class_defs_size', bytes2int(self.class_defs_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'class_defs_off', bytes2int(self.class_defs_off))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'data_size', bytes2int(self.data_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'data_off', bytes2int(self.data_off))


class MapList(object):
    def __init__(self, data, dex):
        self.dexFile = dex
        self.size = bytes2int(dex.buffer[dex.fileHeader.map_off:dex.fileHeader.map_off + 4])
        self.items = [MapItem(dex.buffer[dex.fileHeader.map_off + MapItem.length * i + 4:dex.fileHeader.map_off + MapItem.length * (i + 1) + 4]) for i in xrange(self.size)]

    def show(self, align = ''):
        print '{0}Map item list:'.format(align)
        for i in xrange(len(self.items)):
            print '  {0}item 0x{1:0>4X}:'.format(align, i)
            self.items[i].show(align + '    ')
            

class MapItem(object):
    length = 0x0C
    def __init__(self, data):
        self.type = bytes2int(data[0x00:0x02])
        self.unused = hexDump(data[0x02:0x04])
        self.size = bytes2int(data[0x04:0x08])
        self.offset = bytes2int(data[0x08:0x0C])

    def show(self, align = ''):
        print '{0}{1:10}{2}'.format(align, 'type', DexItemType[self.type])
        print '{0}{1:10}{2}'.format(align, 'unused', self.unused)
        print '{0}{1:10}{2:0>4X}'.format(align, 'size', self.size)
        print '{0}{1:10}{2:0>4X}'.format(align, 'offset', self.offset)


class StringIDs(object):
    def __init__(self, data, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.string_ids_size
        self.offset = dex.fileHeader.string_ids_off
        self.items = [StringItem(dex.buffer, bytes2int(dex.buffer[self.offset + i * 4:self.offset + (i + 1) * 4])) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}String data:'.format(align)
        for i in self.items:
            i.show(align + '  ')

class StringItem(object):
    def __init__(self, data, offset):
        self.size, sizeoflength = leb128(data, offset)
        self.str = data[offset + sizeoflength:offset + sizeoflength + self.size]

    def show(self, align = ''):
        print '{0}{1:0>2X}  {2}'.format(align, self.size, self.str.encode('utf-8').replace('"', '\"').__repr__())
