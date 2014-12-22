DexItemType = {0x0000: 'kDexTypeHeaderItem',
     0x0001: 'kDexTypeStringIdItem',
     0x0002: 'kDexTypeTypeIdItem',
     0x0003: 'kDexTypeProtoIdItem',
     0x0004: 'kDexTypeFieldIdItem',
     0x0005: 'kDexTypeMethodIdItem',
     0x0006: 'kDexTypeClassDefItem',
     0x1000: 'kDexTypeMapList',
     0x1001: 'kDexTypeTypeList',
     0x1002: 'kDexTypeAnnotationSetRefList',
     0x1003: 'kDexTypeAnnotationSetItem',
     0x2000: 'kDexTypeClassDataItem',
     0x2001: 'kDexTypeCodeItem',
     0x2002: 'kDexTypeStringDataItem',
     0x2003: 'kDexTypeDebugInfoItem',
     0x2004: 'kDexTypeAnnotationItem',
     0x2005: 'kDexTypeEncodedArrayItem',
     0x2006: 'kDexTypeAnnotationsDirectoryItem'}

AccessFlags = {0x00000001:'public',
    0x00000002:'private',
    0x00000004:'protected',
    0x00000008:'static',
    0x00000010:'final',
    0x00000020:'synchronized',
    0x00000040:'volatile',
    0x00000080:'bridge',
    0x00000100:'native',
    0x00000200:'interface',
    0x00000400:'abstract',
    0x00000800:'strict',
    0x00001000:'synthetic',
    0x00002000:'annotation',
    0x00004000:'enum',
    0x00010000:'constructor',
    0x00020000:'declared_synchronized'}

ClassPrototype = '''
{0} {
}
'''
