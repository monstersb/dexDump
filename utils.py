#! -*- coding:utf-8 -*-

def readfile(fname):
    with open(fname, 'r') as f:
        return f.read()

def hexDump(data):
    return ' '.join(['%02X' % (ord(i)) for i in data])

def bytes2int(data):
    return sum([(ord(data[i]) << 8 * i) for i in range(len(data))])
