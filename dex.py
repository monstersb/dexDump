#! /usr/bin/env python
#! -*- coding:utf-8 -*-

from utils import *
from constant import *

class DexFile(object):
    def __init__(self, data):
        self.buffer = data[:]
        self.fileHeader = DexFileHeader(self)
        self.mapList = MapList(self)
        self.stringIDs = StringIDs(self)
        self.typeIDs = TypeIDs(self)
        self.typeListIDx = TypeListIDx(self)
        self.protoTypeIDs = ProtoTypeIDs(self)
        self.fieldIDx = FieldIDx(self)
        self.methodIDs = MethodIDs(self)
        self.classDefs = ClassDefs(self)

    def show(self):
        self.fileHeader.show()
        self.mapList.show()
        self.stringIDs.show()
        self.typeIDs.show()
        self.typeListIDx.show()
        self.protoTypeIDs.show()
        self.fieldIDx.show()
        self.methodIDs.show()
        self.classDefs.show()

    def getClasses(self, mfilter = None):
        if not mfilter:
            for i in self.classDefs.items:
                print str(self.stringIDs[self.typeIDs[i.class_idx]]).replace('/', '.')[1:-1]
'''
        for i in self.classDefs.items:
            if str(self.stringIDs[self.typeIDs[i.class_idx]]).replace('/', '.')[1:-1] == mfilter:
                i.show()
                print accessFlags(i.access_flags) + ' class ' + mfilter[mfilter.rfind('/') + 1:] + "{\n"
                break
'''

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
        self.type_ids_size = bytes2int(self.data[0x40:0x44])
        self.type_ids_off = bytes2int(self.data[0x44:0x48])
        self.proto_ids_size = bytes2int(self.data[0x48:0x4C])
        self.proto_ids_off = bytes2int(self.data[0x4C:0x50])
        self.field_ids_size = bytes2int(self.data[0x50:0x54])
        self.field_ids_off = bytes2int(self.data[0x54:0x58])
        self.method_ids_size = bytes2int(self.data[0x58:0x5C])
        self.method_ids_off = bytes2int(self.data[0x5C:0x60])
        self.class_defs_size = bytes2int(self.data[0x60:0x64])
        self.class_defs_off = bytes2int(self.data[0x64:0x68])
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
        print '  {0}{1:18}{2:0>8X}'.format(align, 'type_ids_size', self.type_ids_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'type_ids_off', self.type_ids_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'proto_ids_size', self.proto_ids_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'proto_ids_off', self.proto_ids_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'field_ids_size', self.field_ids_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'field_ids_off', self.field_ids_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'method_ids_size', self.method_ids_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'method_ids_off', self.method_ids_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'class_defs_size', self.class_defs_size)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'class_defs_off', self.class_defs_off)
        print '  {0}{1:18}{2:0>8X}'.format(align, 'data_size', bytes2int(self.data_size))
        print '  {0}{1:18}{2:0>8X}'.format(align, 'data_off', bytes2int(self.data_off))


class MapList(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = bytes2int(dex.buffer[dex.fileHeader.map_off:dex.fileHeader.map_off + 4])
        self.items = [MapItem(dex.buffer[dex.fileHeader.map_off + MapItem.length * i + 4:dex.fileHeader.map_off + MapItem.length * (i + 1) + 4]) for i in xrange(self.size)]

    def show(self, align = ''):
        print '{0}Map item list:'.format(align)
        for i in xrange(len(self.items)):
            print '  {0}item 0x{1:0>4X}:'.format(align, i)
            self.items[i].show(align + '    ')

    def __getitem__(self, key):
        for i in self.items:
            if DexItemType[i.type] == key:
                return i
        return None
            

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
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.string_ids_size
        self.offset = dex.fileHeader.string_ids_off
        self.items = [StringItem(dex.buffer, bytes2int(dex.buffer[self.offset + i * 4:self.offset + (i + 1) * 4])) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}String items:'.format(align)
        for i in self.items:
            i.show(align + '  ')

    def __getitem__(self, key):
        return self.items[key]


class StringItem(object):
    def __init__(self, data, offset):
        self.size, sizeoflength = leb128(data, offset)
        self.str = data[offset + sizeoflength:offset + sizeoflength + self.size].decode('gbk')

    def show(self, align = ''):
        print '{0}{1:0>2X}  {2}'.format(align, self.size, self.str.replace('"', '\"').__repr__())

    def __str__(self):
        return self.str


class TypeIDs(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.type_ids_size
        self.offset = dex.fileHeader.type_ids_off
        self.items = [bytes2int(dex.buffer[self.offset + i * 4:self.offset + (i + 1) * 4]) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}Type items:'.format(align)
        for i in xrange(len(self.items)):
            print '  {0}{1:0>4X}    [{2:0>4X}]    {3}'.format(align, i, self.items[i], self.dexFile.stringIDs[self.items[i]])
            
    def __getitem__(self, key):
        return self.items[key]


class TypeListIDx(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.mapList['kDexTypeTypeList'].size
        self.offset = dex.mapList['kDexTypeTypeList'].offset
        self.items = []
        toff = intAlign(self.offset, 4)
        for i in xrange(self.size):
            item = TypeListItem(toff, self.dexFile)
            toff = intAlign(toff + item.size * 2 + 4, 4)
            self.items.append(item)

    def show(self, align = ''):
        print '{0}Type list items:'.format(align)
        for i in self.items:
            i.show(align + '  ')


class TypeListItem(object):
    def __init__(self, offset, dex):
        self.dexFile = dex
        self.size = bytes2int(dex.buffer[offset:offset + 4])
        self.items = [bytes2int(dex.buffer[offset + i * 2 + 4:offset + (i + 1) * 2 + 4]) for i in xrange(self.size)]

    def show(self, align = ''):
        print '{0}Parameters:'.format(align)
        for i in self.items:
            print '  {0}{1}'.format(align, self.dexFile.stringIDs[self.dexFile.typeIDs[i]])


class ProtoTypeIDs(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.proto_ids_size
        self.offset = dex.fileHeader.proto_ids_off
        self.items = [ProtoTypeItem(self.offset, i, self.dexFile) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}ProtoType items:'.format(align)
        for i in range(len(self.items)):
            print '  {0}Item 0x{1:0>4X}:'.format(align, i)
            self.items[i].show(align + '  ')
            
    def __getitem__(self, key):
        return self.items[key]


class ProtoTypeItem(object):
    length = 0x0C
    def __init__(self, off, i, dex):
        self.dexFile = dex
        self.shortyIDx = bytes2int(dex.buffer[off + i * ProtoTypeItem.length:off + i * ProtoTypeItem.length + 0x04])
        self.returnTypeIDx = bytes2int(dex.buffer[off + i * ProtoTypeItem.length + 0x04:off + i * ProtoTypeItem.length + 0x08])
        self.parametersOff = bytes2int(dex.buffer[off + i * ProtoTypeItem.length + 0x08:off + i * ProtoTypeItem.length + 0x0C])

    def show(self, align = ''):
        print '  {0}{1:15}  {2}'.format(align, 'shorty', self.dexFile.stringIDs[self.shortyIDx])
        print '  {0}{1:15}  {2}'.format(align, 'return_type', self.dexFile.stringIDs[self.dexFile.typeIDs[self.returnTypeIDx]])
        if self.parametersOff != 0:
            parametersList = TypeListItem(self.parametersOff, self.dexFile)
            #print '  {0}{1:15}  {2}'.format(align, 'Parameters_off', self.parametersOff)
            parametersList.show(align + '  ')
        else:
            print '  {0}No parameters'.format(align)


class FieldIDx(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.field_ids_size
        self.offset = dex.fileHeader.field_ids_off
        self.items = [FieldItem(dex, self.offset + i * 8) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}Field items:'.format(align)
        for i in self.items:
            i.show(align + '  ')

    def __getitem__(self, key):
        return self.items[key]

class FieldItem(object):
    def __init__(self, dex, off):
        self.dexFile = dex
        self.class_idx = bytes2int(dex.buffer[off:off + 2])
        self.type_idx = bytes2int(dex.buffer[off + 2:off + 4])
        self.name_idx = bytes2int(dex.buffer[off + 4:off + 8])

    def show(self, align = ''):
        print '{0}Field:'.format(align)
        print '  {0}{1:15}{2}'.format(align, 'class', self.dexFile.stringIDs[self.dexFile.typeIDs[self.class_idx]])
        print '  {0}{1:15}{2}'.format(align, 'type', self.dexFile.stringIDs[self.dexFile.typeIDs[self.type_idx]])
        print '  {0}{1:15}{2}'.format(align, 'name', self.dexFile.stringIDs[self.name_idx])


class MethodIDs(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.method_ids_size
        self.offset = dex.fileHeader.method_ids_off
        self.items = [MethodItem(dex, self.offset + i * 8) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}Method items:'.format(align)
        for i in self.items:
            i.show(align + '  ')
    def __getitem__(self, key):
        return self.items[key]


class MethodItem(object):
    def __init__(self, dex, off):
        self.dexFile = dex
        self.class_idx = bytes2int(dex.buffer[off:off + 2])
        self.proto_idx = bytes2int(dex.buffer[off + 2:off + 4])
        self.name_idx = bytes2int(dex.buffer[off + 4:off + 8])

    def show(self, align = ''):
        print '{0}Method:'.format(align)
        print '  {0}{1:15}{2}'.format(align, 'class', self.dexFile.stringIDs[self.dexFile.typeIDs[self.class_idx]])
        print '  {0}{1}:'.format(align, 'prototype')
        self.dexFile.protoTypeIDs[self.proto_idx].show(align + '  ')
        print '  {0}{1:15}{2}'.format(align, 'name', self.dexFile.stringIDs[self.name_idx])


class CodeItem(object):
    def __init__(self, dex, off):
        self.registers_size = bytes2int(dex.buffer[off + 0x00: off + 0x02])
        self.ins_size = bytes2int(dex.buffer[off + 0x02: off + 0x04])
        self.outs_size = bytes2int(dex.buffer[off + 0x04: off + 0x06])
        self.tries_size = bytes2int(dex.buffer[off + 0x06: off + 0x08])
        self.debug_info_off = bytes2int(dex.buffer[off + 0x08: off + 0x0C])
        self.insns_size = bytes2int(dex.buffer[off + 0x0C: off + 0x10]);
        self.insns = [bytes2int(dex.buffer[off + 0x10 + i * 2: off + 0x10 + (i + 1)]) for i in xrange(self.insns_size)]

    def show(self, align = ''):
        print '{0}Code item:'.format(align)
        print '  {0}{1:18}{2}'.format(align, 'Registers size:', self.registers_size)
        print '  {0}{1:18}{2}'.format(align, 'Ins size:', self.ins_size)
        print '  {0}{1:18}{2}'.format(align, 'Out size:', self.outs_size)
        print '  {0}{1:18}{2}'.format(align, 'Tries size:', self.tries_size)
        print '  {0}{1:18}{2}'.format(align, 'Debug info off:', self.debug_info_off)
        print '  {0}{1:18}{2}'.format(align, 'Insns size:', self.insns_size)

class EncodedField(object):
    def __init__(self, dex, off, field_off):
        self.dexFile = dex
        self.length = 0
        t = leb128(dex.buffer, off)
        self.field_idx = t[0] + field_off
        off = off + t[1]
        self.length = self.length + t[1]
        t = leb128(dex.buffer, off)
        self.access_flags = t[0]
        off = off + t[1]
        self.length = self.length + t[1]

    def show(self, align = ''):
        print '{0}Encoded field:'.format(align)
        self.dexFile.fieldIDx[self.field_idx].show(align + '  ')
        print '  {0}{1:15}{2}'.format(align, 'access flags:', accessFlags(self.access_flags))


class EncodedMethod(object):
    def __init__(self, dex, off, method_off):
        self.dexFile = dex
        self.length = 0
        t = leb128(dex.buffer, off)
        self.method_idx = t[0] + method_off
        off = off + t[1]
        self.length = self.length + t[1]
        t = leb128(dex.buffer, off)
        self.access_flags = t[0]
        off = off + t[1]
        self.length = self.length + t[1]
        t = leb128(dex.buffer, off)
        self.code_off = t[0]
        off = off + t[1]
        self.length = self.length + t[1]

    def show(self, align = ''):
        print '{0}Encoded method:'.format(align)
        self.dexFile.methodIDs[self.method_idx].show(align + '  ')
        print '  {0}{1:15}{2}'.format(align, 'access flags:', accessFlags(self.access_flags))
        CodeItem(self.dexFile, self.code_off).show(align + '  ')


class ClassDataItem(object):
    def __init__(self, dex, off):
        self.offset = off
        t = leb128(dex.buffer, off)
        self.static_fields_size = t[0]
        off = off + t[1]
        t = leb128(dex.buffer, off)
        self.instance_fields_size = t[0]
        off = off + t[1]
        t = leb128(dex.buffer, off)
        self.direct_methods_size = t[0]
        off = off + t[1]
        t = leb128(dex.buffer, off)
        self.virtual_method_size = t[0]
        off = off + t[1]
        self.static_fields = []
        t = 0
        for i in xrange(self.static_fields_size):
            self.static_fields.append(EncodedField(dex, off, t))
            off = off + self.static_fields[-1].length
            t = self.static_fields[-1].field_idx
        self.instance_fields = []
        t = 0
        for i in xrange(self.instance_fields_size):
            self.instance_fields.append(EncodedField(dex, off, t))
            off = off + self.instance_fields[-1].length
            t = self.instance_fields[-1].field_idx
        self.direct_methods = []
        t = 0
        for i in xrange(self.direct_methods_size):
            self.direct_methods.append(EncodedMethod(dex, off, t))
            off = off + self.direct_methods[-1].length
            t = self.direct_methods[-1].method_idx
        self.virtual_methods = []
        t = 0
        for i in xrange(self.virtual_method_size):
            self.virtual_methods.append(EncodedMethod(dex, off, t))
            off = off + self.virtual_methods[-1].length
            t = self.virtual_methods[-1].method_idx

    def show(self, align = ''):
        print '{0}Class data item:'.format(align)
        print '  {0}{1}'.format(align, 'static_fields:')
        for i in self.static_fields:
            i.show(align + '    ')
        print '  {0}{1}'.format(align, 'instance_fields:')
        for i in self.instance_fields:
            i.show(align + '    ')
        print '  {0}{1}'.format(align, 'direct_methods:')
        for i in self.direct_methods:
            i.show(align + '    ')
        print '  {0}{1}'.format(align, 'virtual_method:')
        for i in self.virtual_methods:
            i.show(align + '    ')


class ClassDefs(object):
    def __init__(self, dex):
        self.dexFile = dex
        self.size = dex.fileHeader.class_defs_size
        self.offset = dex.fileHeader.class_defs_off
        self.items = [ClassDefItem(dex, self.offset + i * 0x20) for i in range(self.size)]

    def show(self, align = ''):
        print '{0}Class def item:'.format(align)
        for i in self.items:
            i.show(align + '  ')

    def __getitem__(self, key):
        return self.items[key]


class ClassDefItem(object):
    def __init__(self, dex, off):
        self.dexFile = dex
        self.class_idx = bytes2int(dex.buffer[off + 0x00:off + 0x04])
        self.access_flags = bytes2int(dex.buffer[off + 0x04:off + 0x08])
        self.superclass_idx = bytes2int(dex.buffer[off + 0x08:off + 0x0C])
        self.interfaces_off = bytes2int(dex.buffer[off + 0x0C:off + 0x10])
        self.source_file_idx = bytes2int(dex.buffer[off + 0x10:off + 0x14])
        self.annotations_off = bytes2int(dex.buffer[off + 0x14:off + 0x18])
        self.class_data_off = bytes2int(dex.buffer[off + 0x18:off + 0x1C])
        self.static_value_off = bytes2int(dex.buffer[off + 0x1C:off + 0x20])

    def show(self, align = ''):
        print '{0}Class def:'.format(align)
        print '  {0}{1:18}{2}'.format(align, 'class', self.dexFile.stringIDs[self.dexFile.typeIDs[self.class_idx]])
        print '  {0}{1:18}{2}'.format(align, 'access_flags', accessFlags(self.access_flags))
        print '  {0}{1:18}{2}'.format(align, 'superclass_idx', self.dexFile.stringIDs[self.dexFile.typeIDs[self.superclass_idx]])
        if self.interfaces_off != 0:
            print '  {0}{1}:'.format(align, 'Interfaces')
            TypeListItem(self.interfaces_off, self.dexFile).show(align + '  ')
        if self.source_file_idx != 0xFFFFFFFF:
            print '  {0}{1:18}{2}'.format(align, 'source_file', self.dexFile.stringIDs[self.source_file_idx])
        print '  {0}{1:18}{2:0>8X}'.format(align, 'annotations_off', self.annotations_off)
        if self.class_data_off != 0:
            ClassDataItem(self.dexFile, self.class_data_off).show(align + '  ')
        if self.static_value_off != 0:
            print '  {0}{1:18}{2:0>8X}'.format(align, 'static_value_off', self.static_value_off)
