#! -*- coding:utf-8 -*-

from constant import *

TypeName = {'V':'void', 'Z':'boolean', 'B':'byte', 'S':'short', 'C':'char', 'I':'int', 'J':'long', 'F':'float', 'D':'double'}

def readfile(fname):
    with open(fname, 'r') as f:
        return f.read()

def hexDump(data):
    return ' '.join(['%02X' % (ord(i)) for i in data])

def bytes2int(data):
    return sum([(ord(data[i]) << 8 * i) for i in range(len(data))])

def leb128(data, offset):
    result = 0
    i = 0
    while True:
        result = result | ((ord(data[offset + i]) & 0x7F)  << (7 * i))
        if ord(data[offset + i]) & 0x80 == 0:
            return result, i + 1
        i = i + 1

def intAlign(n, x):
    a, b = divmod(n, x)
    return (a + bool(b)) * 4

def accessFlags(flags):
    return ' '.join([AccessFlags[i] for i in AccessFlags if (flags & i) != 0])

def str2type(data):
    data = str(data)
    if TypeName.has_key(data):
        return TypeName[data] 
    elif data[0] == 'L':
        if data.find('/') == -1:
            return data[1:-1]
        else:
            return data[data.rfind('/') + 1:-1]
    elif data[0] == '[' and TypeName.has_key(data[1:]):
        return TypeName[data[1:]] + '[]'
    elif data[:2] == '[L':
        if data.find('/') == -1:
            return data[2:-1] + '[]'
        else:
            return data[data.rfind('/') - 2:-1] + '[]'
    return data
