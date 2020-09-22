## Reversing ELF - Try Hack Me

## 1. Oversikt

**Reverse Engineering**\
**IDA Pro**\
**Radare**\
**Linux Binaries**\
[Link to the machine](https://tryhackme.com/room/reverselfiles)


## 2. Tasks
### 2.1 crackme1

We simply just run the binary. And in order to make it run, you have to use `chmod +x crackme1`.

### 2.2 crackme2

Ran the binary in IDA pro, and then we see the password in one of the functions. However we could just use the `strings` or the `xxd`command. `strings` will let you see all human readable characters, while `xxd` will let you see a hexview of the binary.

### 2.3 crackme3

We use the same command from crackme2; `strings` and we see a base64 stirng there. We can get this out from the terminal with this command:

```sh
echo ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ== | base64 --decode
```

And we get the password back and run the file with that poassword to get the flag out.


### 2.4 crackme4

We have to use radare2 or IDA for this one. If you run the binary, it will output that the string is now hidden and they have used string compare or strcmp. So we cant simply use `strings` in order to see the password. Here we will use radare2 to complete the task.

First we run radare2 with the file in debug mode:

```sh
radre2 -d crackme4
```

Then we use the command `aaa` in order to analyse the binary. Then we can list all the funtions with the `afl` command. This is the output:
```sh
[0x7f3179eb7090]> afl
0x00400540    1 41           entry0
0x00400510    1 6            sym.imp.__libc_start_main
0x00400570    4 41           sym.deregister_tm_clones
0x004005a0    4 57           sym.register_tm_clones
0x004005e0    3 28           entry.fini0
0x00400600    4 45   -> 42   entry.init0
0x004007d0    1 2            sym.__libc_csu_fini
0x0040062d    4 77           sym.get_pwd
0x004007d4    1 9            sym._fini
0x0040067a    6 156          sym.compare_pwd
0x00400760    4 101          sym.__libc_csu_init
0x00400716    4 74           main
0x004004b0    3 26           sym._init
0x00400530    1 6            loc.imp.__gmon_start
0x004004e0    1 6            sym.imp.puts
0x004004f0    1 6            sym.imp.__stack_chk_fail
0x00400500    1 6            sym.imp.printf
0x00400520    1 6            sym.imp.strcmp

```

We can see that the binary has a *main* function as well as a *get_pwd* and a *compare_pwd*. We can dive further into each function with the `s` commmand. `s` will simply print all the current addresses in a specified function. So we choose the *compare_pwd* function, and then print the output with `pdf` which will disassemble the function for us:

```sh
[0x7f3179eb7090]> s sym.compare_pwd
[0x0040067a]> pdf
/ (fcn) sym.compare_pwd 156
|   sym.compare_pwd (int32_t arg1);
|           ; var int32_t var_28h @ rbp-0x28
|           ; var int32_t var_20h @ rbp-0x20
|           ; var int32_t var_18h @ rbp-0x18
|           ; var int32_t var_10h @ rbp-0x10
|           ; var int32_t var_eh @ rbp-0xe
|           ; var int32_t var_8h @ rbp-0x8
|           ; arg int32_t arg1 @ rdi
|           ; CALL XREF from main @ 0x400754
|           0x0040067a      55             push rbp
|           0x0040067b      4889e5         mov rbp, rsp
|           0x0040067e      4883ec30       sub rsp, 0x30
|           0x00400682      48897dd8       mov qword [var_28h], rdi    ; arg1
|           0x00400686      64488b042528.  mov rax, qword fs:[0x28]
|           0x0040068f      488945f8       mov qword [var_8h], rax
|           0x00400693      31c0           xor eax, eax
|           0x00400695      48b8495d7b49.  movabs rax, 0x7b175614497b5d49
|           0x0040069f      488945e0       mov qword [var_20h], rax
|           0x004006a3      48b857414751.  movabs rax, 0x547b175651474157
|           0x004006ad      488945e8       mov qword [var_18h], rax
|           0x004006b1      66c745f05340   mov word [var_10h], 0x4053  ; 'S@'
|           0x004006b7      c645f200       mov byte [var_eh], 0
|           0x004006bb      488d45e0       lea rax, qword [var_20h]
|           0x004006bf      4889c7         mov rdi, rax
|           0x004006c2      e866ffffff     call sym.get_pwd
|           0x004006c7      488b55d8       mov rdx, qword [var_28h]
|           0x004006cb      488d45e0       lea rax, qword [var_20h]
|           0x004006cf      4889d6         mov rsi, rdx
|           0x004006d2      4889c7         mov rdi, rax
|           0x004006d5      e846feffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
|           0x004006da      85c0           test eax, eax
|       ,=< 0x004006dc      750c           jne 0x4006ea
|       |   0x004006de      bfe8074000     mov edi, str.password_OK    ; 0x4007e8 ; "password OK"
|       |   0x004006e3      e8f8fdffff     call sym.imp.puts           ; int puts(const char *s)
|      ,==< 0x004006e8      eb16           jmp 0x400700
|      |`-> 0x004006ea      488b45d8       mov rax, qword [var_28h]
|      |    0x004006ee      4889c6         mov rsi, rax
|      |    0x004006f1      bff4074000     mov edi, str.password___s__not_OK ; 0x4007f4 ; "password \"%s\" not OK\n"
|      |    0x004006f6      b800000000     mov eax, 0
|      |    0x004006fb      e800feffff     call sym.imp.printf         ; int printf(const char *format)
|      |    ; CODE XREF from sym.compare_pwd @ 0x4006e8
|      `--> 0x00400700      488b45f8       mov rax, qword [var_8h]
|           0x00400704      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x0040070d      7405           je 0x400714
|       |   0x0040070f      e8dcfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x00400714      c9             leave
\           0x00400715      c3             ret
```

So we can see what the function does. The interesting one here is the string compare at the addresss `0x004006d5`. If we then look at the previous address we can try to see what it is comparing our argument to. The strcmp will look at the content of register *rax* and compare it to register *rdi*. So if we look closer into *rdi* we can find the password. We set a breakpoint at the address `0x004006d2` and run the following commands:

```sh
db 0x004006d2
ood 'somethingfunny'
dc
```

`ood 'somethingfunny'` will just pass an argument to the `rax` register. In this case we set it to be 'somethingfunny', but it can be anything, it does not matter. Then we can use `pdf` again to see where our breakpoint is. And then finally we can use the `px` command to see the value of a register. In this case we want to see what *rdi* contains:

```sh
[0x004006d2]> px @rdi
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7fff9bc2c460  6d79 5f6d 3072 335f 7365 6375 7233 5f70  my_m0r3_secur3_p                                               
0x7fff9bc2c470  7764 0000 0000 0000 002c f21c e56d cfe2  wd.......,...m..
0x7fff9bc2c480  a0c4 c29b ff7f 0000 5907 4000 0000 0000  ........Y.@.....
0x7fff9bc2c490  88c5 c29b ff7f 0000 0000 0000 0200 0000  ................
0x7fff9bc2c4a0  6007 4000 0000 0000 bbbb 5f95 277f 0000  `.@......._.'...
0x7fff9bc2c4b0  0000 0000 0000 0000 88c5 c29b ff7f 0000  ................
0x7fff9bc2c4c0  0000 0000 0200 0000 1607 4000 0000 0000  ..........@.....
0x7fff9bc2c4d0  0000 0000 0000 0000 1c25 84d6 56ef 5e77  .........%..V.^w
0x7fff9bc2c4e0  4005 4000 0000 0000 80c5 c29b ff7f 0000  @.@.............
0x7fff9bc2c4f0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff9bc2c500  1c25 2451 53d8 a188 1c25 a2ae 69c5 1189  .%$QS....%..i...
0x7fff9bc2c510  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff9bc2c520  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff9bc2c530  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff9bc2c540  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff9bc2c550  4005 4000 0000 0000 80c5 c29b ff7f 0000  @.@.............
```

And we can see the value that the register holds when it is called by main.

### 2.5 crackme5

Same as in crackem4



### 2.6 crackme6

Using radare2 again to debug the binary. We run the file in debug mode with this command:

```sh
r2 -d crackme6
```

Then we use `aaa` to analyse all functions, followed by `afl` to list all the functions. In the list we see a function called `sym.compare_pwd` and we take a look at it with `pdf @sym.compare_pwd`. `compare_pwd` just compares the string with something we cant see. But that variable is coming from the function `sym.my_secure_test`. It contains a lot of jumps and it is hard to read in the `pdf` mode. So we can use the command `VV`, `vV` or `V!` to enter *graph mode*. This makes it easier to see what the function does, and if we want to execute radare commands we can just use `:`. The function compares each bit of the input with a hex value. Each box is checking a byte and we put the hex values together:

```
0x31
0x33
0x33
0x37
0x5f
0x70
0x77
0x64
```  

We use cyberchef to look at the hex values in ascii (or just look at an ascii table):
```
0x31 = 1
0x33 = 3
0x33 = 3
0x37 = 7
0x5f = _
0x70 = p
0x77 = w
0x64 = d
```  
And now we have the comparison. `The compare_pwd` function is comparing the input from the user to this string. And when we run the binary with this password we get the flag.


### 2.7 crackme7

Start this the same way as the others:

```sh
r2 -d crackme7
```

Then we use `aaa` to analyse all functions, followed by `afl` to list all the functions. We then take a look at main to see what it does. This is done with `s main` followed by `pdf`. In the main function we see a print that is a bit different from the others: *Wow such h4x0r*. This will only print if a compare is correct right before it. It is comparing the input of the user to the hex value `0x7a69`. This hex value is the same as 31337 in decimal, so if we run the binary and pass this number in we get the flag.   


### 2.8 crackme8

Start this the same way as the others:

```sh
r2 -d crackme7
```

Then we use `aaa` to analyse all functions, followed by `afl` to list all the functions. We analyse the main function to see what the binary does. With `s main` followed by `pdf` we see that it does a comparison to the hexvalue 0xcafef00d, almost the same as in crackme7. However, there is a atoi function being called before that. So we can use linux manual page to look at what atoi does. `man atoi` will show that it converts a string to a integer. So the input we give will be converted to a integer. So if we check with an online calculator:

`0xcafef00d` = 3405705229 (DEC)

If we pass this to the file we get "access denied". However:

`0xcafef00d` = 11001010111111101111000000001101 (Binary)

Here we can see that the most significant bit is 1, which means that this HEX value is negative, so we have to check https://www.rapidtables.com/convert/number/hex-to-decimal.html to see the value of `0xcafef00d` in decimal from 2's compliment. And we get the following result:

`0xcafef00d` = -889262067 (DEC from Signed 2's complement)

Ok, so if we pass in this negative number we get the flag out.



## 3. Debugging

If we wanted to see this in a better visual style, we can debug at a certain point and see what is actually happening. This is usefull for all the tasks, but il use crackme8 as an example.

we open radare as usuall with:

`r2 -d crackme8`

Then we use `aaa` followed by `afl` to see all the functions. After this we can check out main with the current command: `s main` and `pdf`

This is the view of main:
```sh
[0xf7f120b0]> s main
[0x0804849b]> pdf
/ (fcn) main 137
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_4h @ ebp-0x4
|           ; arg int32_t arg_4h @ esp+0x4
|           ; DATA XREF from entry0 @ 0x80483b7
|           0x0804849b      8d4c2404       lea ecx, dword [arg_4h]
|           0x0804849f      83e4f0         and esp, 0xfffffff0
|           0x080484a2      ff71fc         push dword [ecx - 4]
|           0x080484a5      55             push ebp
|           0x080484a6      89e5           mov ebp, esp
|           0x080484a8      51             push ecx
|           0x080484a9      83ec04         sub esp, 4
|           0x080484ac      89c8           mov eax, ecx
|           0x080484ae      833802         cmp dword [eax], 2
|       ,=< 0x080484b1      741d           je 0x80484d0
|       |   0x080484b3      8b4004         mov eax, dword [eax + 4]
|       |   0x080484b6      8b00           mov eax, dword [eax]
|       |   0x080484b8      83ec08         sub esp, 8
|       |   0x080484bb      50             push eax
|       |   0x080484bc      6860860408     push str.Usage:__s_password ; 0x8048660 ; "Usage: %s password\n"
|       |   0x080484c1      e87afeffff     call sym.imp.printf         ; int printf(const char *format)
|       |   0x080484c6      83c410         add esp, 0x10
|       |   0x080484c9      b801000000     mov eax, 1
|      ,==< 0x080484ce      eb4c           jmp 0x804851c
|      |`-> 0x080484d0      8b4004         mov eax, dword [eax + 4]
|      |    0x080484d3      83c004         add eax, 4
|      |    0x080484d6      8b00           mov eax, dword [eax]
|      |    0x080484d8      83ec0c         sub esp, 0xc
|      |    0x080484db      50             push eax
|      |    0x080484dc      e89ffeffff     call sym.imp.atoi           ; int atoi(const char *str)
|      |    0x080484e1      83c410         add esp, 0x10
|      |    0x080484e4      3d0df0feca     cmp eax, 0xcafef00d
|      |,=< 0x080484e9      7417           je 0x8048502
|      ||   0x080484eb      83ec0c         sub esp, 0xc
|      ||   0x080484ee      6874860408     push str.Access_denied.     ; 0x8048674 ; "Access denied."
|      ||   0x080484f3      e858feffff     call sym.imp.puts           ; int puts(const char *s)
|      ||   0x080484f8      83c410         add esp, 0x10
|      ||   0x080484fb      b801000000     mov eax, 1
|     ,===< 0x08048500      eb1a           jmp 0x804851c
|     ||`-> 0x08048502      83ec0c         sub esp, 0xc
|     ||    0x08048505      6883860408     push str.Access_granted.    ; 0x8048683 ; "Access granted."
|     ||    0x0804850a      e841feffff     call sym.imp.puts           ; int puts(const char *s)
|     ||    0x0804850f      83c410         add esp, 0x10
|     ||    0x08048512      e80d000000     call sym.giveFlag
|     ||    0x08048517      b800000000     mov eax, 0
|     ||    ; CODE XREFS from main @ 0x80484ce, 0x8048500
|     ``--> 0x0804851c      8b4dfc         mov ecx, dword [var_4h]
|           0x0804851f      c9             leave
|           0x08048520      8d61fc         lea esp, dword [ecx - 4]
\           0x08048523      c3             ret
[0x0804849b]>
```

If we want to debug the probram we can use the `db <address>` command  
So lets take a look at the comparison at address 0x080484e4, and put in a test variable as the input with `ood`. Then we run the binary with `dc`

```sh
db 0x080484e4
ood 'test'
dc
```

If everything is ok we should see a `b` at the correct address if we use `pdf`. Then we can use the graph mode to see what is happening, and see the registers and how they change as we step through the function. The command is `V!` followed by using `s` each time we want it to step forward. On the bottom right hand side we can see the registers and their values. This is super usefull.

If we passed the string 'test' with `ood`, graph mode will show that the eax register is just filled with zeroes. However, if we pass it the xcorrect number, we can indeed see that the register contains `0xcafef00d`, and the comparrison will be correct.
