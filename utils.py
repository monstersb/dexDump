#! -*- coding:utf-8 -*-

from constant import *

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
