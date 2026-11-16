"""Check the source parser against a small inert PE image built in memory."""
import struct
import pefile

data=bytearray(1024)
data[:2]=b'MZ'
struct.pack_into('<I',data,0x3c,0x80)
data[0x80:0x84]=b'PE\0\0'
struct.pack_into('<HHIIIHH',data,0x84,0x14c,1,0,0,0,224,0x102)
optional=0x98
struct.pack_into('<H',data,optional,0x10b)
for offset,value in [(16,0x1000),(28,0x400000),(32,0x1000),(36,0x200),(56,0x2000),(60,0x200),(92,16)]:
    struct.pack_into('<I',data,optional+offset,value)
section=optional+224
data[section:section+8]=b'.text\0\0\0'
struct.pack_into('<IIII',data,section+8,16,0x1000,512,512)
struct.pack_into('<I',data,section+36,0x60000020)
data[512]=0xc3
image=pefile.PE(data=bytes(data))
assert image.FILE_HEADER.Machine==0x14c and len(image.sections)==1
assert image.get_data(image.OPTIONAL_HEADER.AddressOfEntryPoint,1)==b'\xc3'
print('PE header, section mapping and inert entry-point bytes: passed')
