# DexDump
### A tool to display information about specified dex file  
---------------------------
```
[monster@localhost]~/Develop/dexDump% ./main.py hello.dex       
Dex file header:
  magic             64 65 78 0A 30 33 35 00
  checksum          80 B7 BA 0F
  signature         DF F6 CD A5 7B DE D9 96 A5 0E FA FA 9D 94 36 43 78 76 B3 D6
  file_size         0000051C
  header_size       00000070
  endian_tag        12345678
  link_size         00000000
  link_off          00000000
  map_off           00000458
  string_ids_size   00000022
  string_ids_off    00000070
  type_ids_size     0000000C
  type_ids_off      000000F8
  proto_ids_size    00000007
  proto_ids_off     00000128
  field_ids_size    00000001
  field_ids_off     0000017C
  method_ids_size   00000009
  method_ids_off    00000184
  class_defs_size   00000001
  class_defs_off    000001CC
  data_size         00000330
  data_off          000001EC
Map item list:
  item 0x0000:
    type      kDexTypeHeaderItem
    unused    00 00
    size      0001
    offset    0000
  item 0x0001:
    type      kDexTypeStringIdItem
    unused    00 00
    size      0022
    offset    0070
  item 0x0002:
    type      kDexTypeTypeIdItem
    unused    00 00
    size      000C
    offset    00F8
  item 0x0003:
    type      kDexTypeProtoIdItem
    unused    00 00
    size      0007
    offset    0128
  item 0x0004:
    type      kDexTypeFieldIdItem
    unused    00 00
    size      0001
    offset    017C
  item 0x0005:
    type      kDexTypeMethodIdItem
    unused    00 00
    size      0009
    offset    0184
  item 0x0006:
    type      kDexTypeClassDefItem
    unused    00 00
    size      0001
    offset    01CC
  item 0x0007:
    type      kDexTypeAnnotationSetItem
    unused    00 00
    size      0001
    offset    01EC
  item 0x0008:
    type      kDexTypeCodeItem
    unused    00 00
    size      0003
    offset    01F4
  item 0x0009:
    type      kDexTypeAnnotationsDirectoryItem
    unused    00 00
    size      0001
    offset    0284
  item 0x000A:
    type      kDexTypeTypeList
    unused    00 00
    size      0004
    offset    029C
  item 0x000B:
    type      kDexTypeStringDataItem
    unused    00 00
    size      0022
    offset    02BA
  item 0x000C:
    type      kDexTypeDebugInfoItem
    unused    00 00
    size      0003
    offset    0427
  item 0x000D:
    type      kDexTypeAnnotationItem
    unused    00 00
    size      0001
    offset    043C
  item 0x000E:
    type      kDexTypeClassDataItem
    unused    00 00
    size      0001
    offset    0444
  item 0x000F:
    type      kDexTypeMapList
    unused    00 00
    size      0001
    offset    0458
String items:
  03  '128'
  03  '512'
  06  '<init>'
  01  'I'
  02  'IL'
  03  'ILL'
  01  'L'
  02  'LI'
  06  'LMain;'
  1A  'Ldalvik/annotation/Throws;'
  15  'Ljava/io/PrintStream;'
  15  'Ljava/lang/Exception;'
  13  'Ljava/lang/Integer;'
  12  'Ljava/lang/Object;'
  12  'Ljava/lang/String;'
  19  'Ljava/lang/StringBuilder;'
  12  'Ljava/lang/System;'
  09  'Main.java'
  01  'V'
  02  'VL'
  13  '[Ljava/lang/String;'
  01  'a'
  06  'append'
  04  'args'
  01  'b'
  0F  'hello world => '
  04  'main'
  07  'monster'
  03  'out'
  08  'parseInt'
  07  'println'
  04  'this'
  08  'toString'
  05  'value'
Type items:
  0000    [0003]    I
  0001    [0008]    LMain;
  0002    [0009]    Ldalvik/annotation/Throws;
  0003    [000A]    Ljava/io/PrintStream;
  0004    [000B]    Ljava/lang/Exception;
  0005    [000C]    Ljava/lang/Integer;
  0006    [000D]    Ljava/lang/Object;
  0007    [000E]    Ljava/lang/String;
  0008    [000F]    Ljava/lang/StringBuilder;
  0009    [0010]    Ljava/lang/System;
  000A    [0012]    V
  000B    [0014]    [Ljava/lang/String;
Type list items:
  Parameters:
    Ljava/lang/String;
  Parameters:
    Ljava/lang/String;
    Ljava/lang/String;
  Parameters:
    I
  Parameters:
    [Ljava/lang/String;
ProtoType items:
  Item 0x0000:
    shorty_idx       IL
    return_type_idx  I
    parameters_off   668
    Parameters:
      Ljava/lang/String;
  Item 0x0001:
    shorty_idx       ILL
    return_type_idx  I
    parameters_off   676
    Parameters:
      Ljava/lang/String;
      Ljava/lang/String;
  Item 0x0002:
    shorty_idx       L
    return_type_idx  Ljava/lang/String;
    No parameters
  Item 0x0003:
    shorty_idx       LI
    return_type_idx  Ljava/lang/StringBuilder;
    parameters_off   684
    Parameters:
      I
  Item 0x0004:
    shorty_idx       V
    return_type_idx  V
    No parameters
  Item 0x0005:
    shorty_idx       VL
    return_type_idx  V
    parameters_off   668
    Parameters:
      Ljava/lang/String;
  Item 0x0006:
    shorty_idx       VL
    return_type_idx  V
    parameters_off   692
    Parameters:
      [Ljava/lang/String;
Field item:
  Field:
    class_idx      9
    type_idx       Ljava/io/PrintStream;
    name_idx       28
```
