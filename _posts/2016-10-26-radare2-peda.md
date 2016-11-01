---
layout: post
title: "radare2 as an alternative to gdb-peda"
date: 2016-10-26 00:25:06
description: A comparison between radare2 and the GDB-PEDA extension
tags:
 - radare2
share: true
---

Many people feel discouraged or overwhelmed to use [radare2](https://github.com/radare/radare2) due to its complexity (understandably so). They often use gdb with the downright amazing [PEDA extension](https://github.com/longld/peda) for their debugging needs and [IDA Pro](https://www.hex-rays.com/products/ida/) for disassembly (or [Hopper](https://www.hopperapp.com/)/[Binary Ninja](https://binary.ninja/) if the price of IDA is too prohibitive).

But you can do both static and dynamic analysis using radare2, with comparable features to gdb-peda on the dynamic front. In this post, I'm going to illustrate this better; perhaps then r2 won't seem so daunting to use.

# Debugger mode

To open a binary in debug mode, either specify the `-d` option in the command line,

{% highlight bash %}
$ r2 -d /path/to/binary
{% endhighlight bash %}

Or, if you've already performed some analysis, you can reopen it in debug mode using `ood` or `doo`; all custom flags will still be there.

# Diassemble

## PEDA
{% highlight nasm %}
gdb-peda$ pdis main
Dump of assembler code for function main:
-----------------------------SNIP------------------------------
   0x08048557 <+121>:	push   eax
   0x08048558 <+122>:	call   0x804846b <func>
   0x0804855d <+127>:	add    esp,0x8
   0x08048560 <+130>:	test   eax,eax
   0x08048562 <+132>:	jne    0x8048574 <main+150>
   0x08048564 <+134>:	sub    esp,0xc
   0x08048567 <+137>:	push   0x8048620
   0x0804856c <+142>:	call   0x8048340 <puts@plt>
   0x08048571 <+147>:	add    esp,0x10
   0x08048574 <+150>:	mov    eax,0x0
   0x08048579 <+155>:	mov    edx,DWORD PTR [ebp-0xc]
   0x0804857c <+158>:	xor    edx,DWORD PTR gs:0x14
   0x08048583 <+165>:	je     0x804858a <main+172>
   0x08048585 <+167>:	call   0x8048330 <__stack_chk_fail@plt>
   0x0804858a <+172>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x0804858d <+175>:	leave  
   0x0804858e <+176>:	lea    esp,[ecx-0x4]
   0x08048591 <+179>:	ret
{% endhighlight nasm %}

## radare2
{% highlight nasm %}
[0x08048558]> pdf @ main
-------------------------------------------SNIP--------------------------------------------
│           0x08048557      50             push eax
│           0x08048558      e80effffff     call sym.func
│           0x0804855d      83c408         add esp, 8
│           0x08048560      85c0           test eax, eax
│       ┌─< 0x08048562      7510           jne 0x8048574
│       │   0x08048564      83ec0c         sub esp, 0xc
│       │   0x08048567      6820860408     push str.Okay ; str.Okay    ; "Okay" @ 0x8048620
│       │   0x0804856c      e8cffdffff     call sym.imp.puts
│       │   0x08048571      83c410         add esp, 0x10
│       └─> 0x08048574      b800000000     mov eax, 0
│           0x08048579      8b55f4         mov edx, dword [ebp - local_ch]
│           0x0804857c      653315140000.  xor edx, dword gs:[0x14]
│       ┌─< 0x08048583      7405           je 0x804858a
│       │   0x08048585      e8a6fdffff     call sym.imp.__stack_chk_fail
│       └─> 0x0804858a      8b4dfc         mov ecx, dword [ebp - local_4h_2]
│           0x0804858d      c9             leave
│           0x0804858e      8d61fc         lea esp, [ecx - 4]
└           0x08048591      c3             ret
{% endhighlight nasm %}

# Checking DEP/PIC and other things

## PEDA

In peda, you have the `checksec` command, which gives varying information about the security fortification of the debugged binary.
{% highlight nasm %}
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
{% endhighlight nasm %}

## radare2

In radare2, you can view a lot of information about the loaded binary using `i`.

{% highlight nasm %}
[0x7f5082528cc0]> i
type     EXEC (Executable file)
file     /bin/ls
referer  dbg:///bin/ls
fd       25226
iorw     true
blksz    0x0
mode     -rwx
block    0x100
format   elf64
havecode true
pic      false
canary   true
nx       true
crypto   false
va       true
intrp    /lib64/ld-linux-x86-64.so.2
bintype  elf
class    ELF64
lang     c
arch     x86
bits     64
machine  AMD x86-64 architecture
os       linux
minopsz  1
maxopsz  16
pcalign  0
subsys   linux
endian   little
stripped true
static   false
linenum  false
lsyms    false
relocs   false
rpath    NONE
binsz    124726
{% endhighlight nasm %}

We can filter out any information that's irrelevant to us using the internal grep operator (`~`)

{% highlight nasm %}
[0x7f5082528cc0]> i~pic,canary,nx,crypto,stripped,static,relocs
pic      false
canary   true
nx       true
crypto   false
stripped true
static   false
relocs   false
{% endhighlight nasm %}

# (Un)setting ASLR

## PEDA

In peda, you can check/disable ASLR using `aslr`

```
gdb-peda$ aslr
ASLR is ON
gdb-peda$ aslr off
gdb-peda$ aslr
ASLR is OFF
```

## radare2

You can use `rarun2` to run a binary with a custom environment. Again, use `radare2` to debug.

{% highlight bash %}
$ r2 -d rarun2 program=/bin/ls aslr=no
{% endhighlight bash %}

The problem with `rarun2` is that it tries to write to `/proc/sys/kernel/randomize_va_space`; you need to be root to do that. I'm not sure how gdb disables ASLR at a user level.

# Function argument detection

## PEDA

PEDA does some neat argument guessing whenever a `call <function>` instruction is reached:

{% highlight nasm %}
[-------------------------------------code-------------------------------------]
   0x8048553 <main+117>:	push   eax
   0x8048554 <main+118>:	lea    eax,[ebp-0x2c]
   0x8048557 <main+121>:	push   eax
=> 0x8048558 <main+122>:	call   0x804846b <func>
   0x804855d <main+127>:	add    esp,0x8
   0x8048560 <main+130>:	test   eax,eax
   0x8048562 <main+132>:	jne    0x8048574 <main+150>
   0x8048564 <main+134>:	sub    esp,0xc
Guessed arguments:
arg[0]: 0xff81a4cc ("This is arg1")
arg[1]: 0xff81a4da ("And this is arg2")
{% endhighlight nasm %}

## radare2

It's pretty close to doing this automatically. You still have to look for them on the stack and registers; see how to dereference below.

# ROP gadgets

## PEDA

In PEDA, you can use `dumprop` to dump all ROP gadgets within a memory range and with a specific maximum depth.

## radare2

You can customize a few options for gadget hunting within radare2.

{% highlight nasm %}
[0x00402a00]> e?rop
        rop.comments: Display comments in rop search output
     rop.conditional: Include conditional jump, calls and returns in ropsearch
              rop.db: Store rop search results in sdb
             rop.len: Maximum ROP gadget length
              rop.nx: Include NX/XN/XD sections in ropsearch
       rop.subchains: Display every length gadget from rop.len=X to 2 in /Rl
{% endhighlight nasm %}

You can search for gadgets using either `/R` or `/Rl` (display in linear fashion, just like `dumprop`). There are also the `/R/` and `/Rl/` variants which allow the use of regular expressions in your search.

{% highlight nasm %}
[0x080482f0]> e rop.len=2
[0x080482f0]> "/Rl add esp;ret"
0x0807ecb9: add esp, 4; ret;
0x08089a67: add esp, dword [ebx + eax*4]; ret;
0x0808f570: add esp, 0x3c; ret;
0x080dbd37: add esp, dword [esi + 0xa]; ret;
0x080df4cf: add esp, dword [edx + 0xa]; ret;
0x080df667: add esp, dword [eax + 0xa]; ret;
0x080df815: add esp, dword [ebp + 0xa]; ret;
0x080dfd5b: add esp, dword [esi + 0xa]; ret;
[0x080482f0]> "/Rl mov dword;ret"
0x08048c12: mov dword [edx + 0x18], eax; ret;
-------------------[SNIP]---------------------
{% endhighlight nasm %}

# Searching for specific instructions

## PEDA

Note: needs `nasm` to be installed.

{% highlight nasm %}
gdb-peda$ asmsearch "pop ?;ret" 0x08048000 0x08049000
Searching for ASM code: 'pop ?;ret' in range: 0x8048000 - 0x8049000
0x08048311 : (5bc3)	pop    ebx;	ret
0x080485fb : (5dc3)	pop    ebp;	ret
0x08048616 : (5bc3)	pop    ebx;	ret
gdb-peda$ asmsearch "inc ?;pop ?" 0x08048000 0x08049000
Searching for ASM code: 'inc ?;pop ?' in range: 0x8048000 - 0x8049000
0x08048281 : (435f)	inc    ebx;	pop    edi
0x0804828b : (435f)	inc    ebx;	pop    edi
{% endhighlight nasm %}

## radare2

{% highlight nasm %}
[0x080484de]> "/c pop;ret"
0x08048312   # 2: pop ebx; ret
0x080485fc   # 2: pop ebp; ret
0x08048617   # 2: pop ebx; ret
[0x080484de]> "/c inc;pop"
0x08048282   # 2: inc ebx; pop edi
0x0804828c   # 2: inc ebx; pop edi
{% endhighlight nasm %}

# ELF header information

## PEDA
```
gdb-peda$ elfheader
.interp = 0x8048154
.note.ABI-tag = 0x8048168
.note.gnu.build-id = 0x8048188
.gnu.hash = 0x80481ac
.dynsym = 0x80481cc
.dynstr = 0x804822c
.gnu.version = 0x8048292
.gnu.version_r = 0x80482a0
.rel.dyn = 0x80482d0
.rel.plt = 0x80482d8
.init = 0x80482f0
.plt = 0x8048320
.plt.got = 0x8048360
.text = 0x8048370
.fini = 0x8048604
.rodata = 0x8048618
.eh_frame_hdr = 0x8048648
.eh_frame = 0x804867c
.init_array = 0x8049f08
.fini_array = 0x8049f0c
.jcr = 0x8049f10
.dynamic = 0x8049f14
.got = 0x8049ffc
.got.plt = 0x804a000
.data = 0x804a018
.bss = 0x804a020
```

## radare2
```
[0x080484de]> iS~ehdr
idx=40 vaddr=0x08048000 paddr=0x00000000 sz=52 vsz=52 perm=m-rw- name=ehdr
[0x080484de]> s 0x08048000
[0x08048000]> pfo elf32     # Load ELF header format
[0x08048000]> pf.elf_header # Print formatted as ELF header struct
     ident : 0x08048000 = .ELF...
      type : 0x08048010 = type (enum elf_type) = 0x2 ; ET_EXEC
   machine : 0x08048012 = machine (enum elf_machine) = 0x3 ; EM_386
   version : 0x08048014 = 0x00000001
     entry : 0x08048018 = 0x08048370
     phoff : 0x0804801c = 0x00000034
     shoff : 0x08048020 = 0x0000181c
     flags : 0x08048024 = 0x00000000
    ehsize : 0x08048028 = 0x0034
 phentsize : 0x0804802a = 0x0020
     phnum : 0x0804802c = 0x0009
 shentsize : 0x0804802e = 0x0028
     shnum : 0x08048030 = 0x001f
  shstrndx : 0x08048032 = 0x001c
[0x08048000]> pf.elf_phdr @ 0x08048034
   type : 0x08048034 = type (enum elf_p_type) = 0x6 ; PT_PHDR
 offset : 0x08048038 = 0x00000034
  vaddr : 0x0804803c = 0x08048034
  paddr : 0x08048040 = 0x08048034
 filesz : 0x08048044 = 0x00000120
  memsz : 0x08048048 = 0x00000120
  flags : 0x0804804c = flags (enum elf_p_flags) = 0x5 ; PF_Read_Exec
  align : 0x08048050 = 0x00000004
```

What about section information?

```
[0x08048000]> iS
[Sections]
idx=00 vaddr=0x00000000 paddr=0x00000000 sz=0 vsz=0 perm=----- name=
idx=01 vaddr=0x08048154 paddr=0x00000154 sz=19 vsz=19 perm=--r-- name=.interp
idx=02 vaddr=0x08048168 paddr=0x00000168 sz=32 vsz=32 perm=--r-- name=.note.ABI_tag
idx=03 vaddr=0x08048188 paddr=0x00000188 sz=36 vsz=36 perm=--r-- name=.note.gnu.build_id
idx=04 vaddr=0x080481ac paddr=0x000001ac sz=32 vsz=32 perm=--r-- name=.gnu.hash
idx=05 vaddr=0x080481cc paddr=0x000001cc sz=96 vsz=96 perm=--r-- name=.dynsym
idx=06 vaddr=0x0804822c paddr=0x0000022c sz=101 vsz=101 perm=--r-- name=.dynstr
idx=07 vaddr=0x08048292 paddr=0x00000292 sz=12 vsz=12 perm=--r-- name=.gnu.version
idx=08 vaddr=0x080482a0 paddr=0x000002a0 sz=48 vsz=48 perm=--r-- name=.gnu.version_r
idx=09 vaddr=0x080482d0 paddr=0x000002d0 sz=8 vsz=8 perm=--r-- name=.rel.dyn
idx=10 vaddr=0x080482d8 paddr=0x000002d8 sz=24 vsz=24 perm=--r-- name=.rel.plt
idx=11 vaddr=0x080482f0 paddr=0x000002f0 sz=35 vsz=35 perm=--r-x name=.init
idx=12 vaddr=0x08048320 paddr=0x00000320 sz=64 vsz=64 perm=--r-x name=.plt
idx=13 vaddr=0x08048360 paddr=0x00000360 sz=8 vsz=8 perm=--r-x name=.plt.got
idx=14 vaddr=0x08048370 paddr=0x00000370 sz=658 vsz=658 perm=--r-x name=.text
idx=15 vaddr=0x08048604 paddr=0x00000604 sz=20 vsz=20 perm=--r-x name=.fini
idx=16 vaddr=0x08048618 paddr=0x00000618 sz=45 vsz=45 perm=--r-- name=.rodata
idx=17 vaddr=0x08048648 paddr=0x00000648 sz=52 vsz=52 perm=--r-- name=.eh_frame_hdr
idx=18 vaddr=0x0804867c paddr=0x0000067c sz=236 vsz=236 perm=--r-- name=.eh_frame
idx=19 vaddr=0x08049f08 paddr=0x00000f08 sz=4 vsz=4 perm=--rw- name=.init_array
idx=20 vaddr=0x08049f0c paddr=0x00000f0c sz=4 vsz=4 perm=--rw- name=.fini_array
idx=21 vaddr=0x08049f10 paddr=0x00000f10 sz=4 vsz=4 perm=--rw- name=.jcr
idx=22 vaddr=0x08049f14 paddr=0x00000f14 sz=232 vsz=232 perm=--rw- name=.dynamic
idx=23 vaddr=0x08049ffc paddr=0x00000ffc sz=4 vsz=4 perm=--rw- name=.got
idx=24 vaddr=0x0804a000 paddr=0x00001000 sz=24 vsz=24 perm=--rw- name=.got.plt
idx=25 vaddr=0x0804a018 paddr=0x00001018 sz=8 vsz=8 perm=--rw- name=.data
idx=26 vaddr=0x0804a020 paddr=0x00001020 sz=4 vsz=4 perm=--rw- name=.bss
idx=27 vaddr=0x00000000 paddr=0x00001020 sz=52 vsz=52 perm=----- name=.comment
idx=28 vaddr=0x00000000 paddr=0x00001712 sz=266 vsz=266 perm=----- name=.shstrtab
idx=29 vaddr=0x00000000 paddr=0x00001054 sz=1136 vsz=1136 perm=----- name=.symtab
idx=30 vaddr=0x00000000 paddr=0x000014c4 sz=590 vsz=590 perm=----- name=.strtab
idx=31 vaddr=0x08048034 paddr=0x00000034 sz=288 vsz=288 perm=m-r-x name=PHDR
idx=32 vaddr=0x08048154 paddr=0x00000154 sz=19 vsz=19 perm=m-r-- name=INTERP
idx=33 vaddr=0x08048000 paddr=0x00000000 sz=1896 vsz=1896 perm=m-r-x name=LOAD0
idx=34 vaddr=0x08049f08 paddr=0x00000f08 sz=280 vsz=284 perm=m-rw- name=LOAD1
idx=35 vaddr=0x08049f14 paddr=0x00000f14 sz=232 vsz=232 perm=m-rw- name=DYNAMIC
idx=36 vaddr=0x08048168 paddr=0x00000168 sz=68 vsz=68 perm=m-r-- name=NOTE
idx=37 vaddr=0x08048648 paddr=0x00000648 sz=52 vsz=52 perm=m-r-- name=GNU_EH_FRAME
idx=38 vaddr=0x00000000 paddr=0x00000000 sz=0 vsz=0 perm=m-rw- name=GNU_STACK
idx=39 vaddr=0x08049f08 paddr=0x00000f08 sz=248 vsz=248 perm=m-r-- name=GNU_RELRO
idx=40 vaddr=0x08048000 paddr=0x00000000 sz=52 vsz=52 perm=m-rw- name=ehdr

41 sections
```

# Cross-references

This is a very useful feature to find out who calls/references what, whether it be an interesting function or string.

## PEDA

{% highlight nasm %}
gdb-peda$ xrefs func
All references to 'func':
0x8048558 <main+122>:	call   0x804846b <func>
{% endhighlight nasm %}

## radare2

{% highlight nasm %}
[0x080484e2]> axt sym.func
call 0x8048558 call sym.func in sym.main
{% endhighlight nasm %}

This can also be done in visual mode using `x` on a specific symbol.

# Patching code/memory

## PEDA

```
gdb-peda$ patch 0x402a00 0x90
Written 1 bytes to 0x402a00
```

## radare2

If opening in read-only mode, you should enable cache-writing via `e io.cache = true`. Otherwise, you can use the `-w` option when loading the file: `r2 -d -w ./binary`.

{% highlight nasm %}
$ r2 /bin/ls
[0x004049a0]> e io.cache = true
[0x004049a0]> pi 1 @ main
push r15
[0x004049a0]> wx 90 @ main
[0x004049a0]> pi 1 @ main
nop
{% endhighlight nasm %}

# De Bruijn patterns

## PEDA

```
gdb-peda$ pattc 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ patto AAEA
AAEA found at offset: 34
```

## radare2

In r2, you need to specify the address at which you wish to write the pattern. AFAIK, there is no way to write the pattern to `stdout` for copy-pasting it. Also, the offset doesn't work with string values; must be hex.

{% highlight nasm %}
[0x00402a00]> wop?
|Usage: wop[DO] len @ addr | value
| wopD len [@ addr]  Write a De Bruijn Pattern of length 'len' at address 'addr'
| wopO value         Finds the given value into a De Bruijn Pattern at current offset
[0x00402a00]> wopD 100 @ rsi
[0x00402a00]> ps @ rsi!100
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
[0x00402a00]> wopO 0x414b4141
28
{% endhighlight nasm %}

# Searching in memory

## PEDA
```
gdb-peda$ phelp searchmem
Search for a pattern in memory; support regex search
Usage:
    searchmem pattern start end
    searchmem pattern mapname
```

## radare2

{% highlight nasm %}
[0x004049a0]> /?
|Usage: /[amx/] [arg]Search stuff (see 'e??search' for options)
| / foo\x00           search for string 'foo\0'
| /j foo\x00          search for string 'foo\0' (json output)
| /! ff               search for first occurrence not matching
| /+ /bin/sh          construct the string with chunks
| /!x 00              inverse hexa search (find first byte != 0x00)
| //                  repeat last search
| /h[t] [hash] [len]  find block matching this hash. See /#?
| /a jmp eax          assemble opcode and search its bytes
| /A jmp              find analyzed instructions of this type (/A? for help)
| /b                  search backwards
| /B                  search recognized RBin headers
| /c jmp [esp]        search for asm code
| /C[ar]              search for crypto materials
| /d 101112           search for a deltified sequence of bytes
| /e /E.F/i           match regular expression
| /E esil-expr        offset matching given esil expressions %%= here 
| /i foo              search for string 'foo' ignoring case
| /m magicfile        search for matching magic file (use blocksize)
| /p patternsize      search for pattern of given size
| /P                  show offset of previous instruction
| /r sym.printf       analyze opcode reference an offset
| /R [grepopcode]     search for matching ROP gadgets, semicolon-separated
| /v[1248] value      look for an `asm.bigendian` 32bit value
| /V[1248] min max    look for an `asm.bigendian` 32bit value in range
| /w foo              search for wide string 'f\0o\0o\0'
| /wi foo             search for wide string ignoring case 'f\0o\0o\0'
| /x ff..33           search for hex string ignoring some nibbles
| /x ff0033           search for hex string
| /x ff43 ffd0        search for hexpair with mask
| /z min max          search for strings of given size
{% endhighlight nasm %}

# Shellcoding

## PEDA
```
gdb-peda$ shellcode
Error: missing argument
Generate or download common shellcodes.
Usage:
    shellcode generate [arch/]platform type [port] [host]
    shellcode search keyword (use % for any character wildcard)
    shellcode display shellcodeId (shellcodeId as appears in search results)
    shellcode zsc [generate customize shellcode]

    For generate option:
        default port for bindport shellcode: 16706 (0x4142)
        default host/port for connect back shellcode: 127.127.127.127/16706
        supported arch: x86

gdb-peda$ shellcode generate
Available shellcodes:
    x86/linux exec
    x86/linux connect
    x86/linux bindport
    x86/bsd exec
    x86/bsd connect
    x86/bsd bindport

gdb-peda$ shellcode generate x86/linux exec
# x86/linux/exec: 24 bytes
shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
    "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)
```

## radare2

{% highlight nasm %}
[0x004049a0]> g?
|Usage: g[wcilper] [arg]Go compile shellcodes
| g foo.r         Compile r_egg source file
| gw              Compile and write
| gc cmd=/bin/ls  Set config option for shellcodes and encoders
| gc              List all config options
| gl              List plugins (shellcodes, encoders)
| gs name args    Compile syscall name(args)
| gi exec         Compile shellcode. like ragg2 -i
| gp padding      Define padding for command
| ge xor          Specify an encoder
| gr              Reset r_egg
| EVAL VARS:      asm.arch, asm.bits, asm.os
[0x004049a0]> gl
shc    exec : execute cmd=/bin/sh suid=false
enc     xor : xor encoder for shellcode
[0x00000000]> gi exec
[0x00000000]> g
31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05
[0x00000000]> 
[0x00000000]> wx `g`
[0x00000000]> pi 13
xor eax, eax
movabs rbx, 0xff978cd091969dd1
neg rbx
push rbx
push rsp
pop rdi
cdq
push rdx
push rdi
push rsp
pop rsi
mov al, 0x3b
syscall
{% endhighlight nasm %}

You can write your own shellcode for future use and compile it. Also, you can write the shellcode anywhere by using the `@` address specifier.

# Tracing

## PEDA

`tracecall` and `traceinst` are very useful in a number of situations.

## radare2

Sadly [broken](https://github.com/radare/radare2/issues/5473) at the moment.

# Virtual memory mapping

Using `vmm` in peda? In r2, it's `dm`.

# Dereferencing stack and registers (telescoping)

## PEDA
{% highlight nasm %}
gdb-peda$ telescope 10
0000| 0x7fff1225eed8 --> 0x7fb93f6b9830 (<__libc_start_main+240>:	mov    edi,eax)
0008| 0x7fff1225eee0 --> 0x0 
0016| 0x7fff1225eee8 --> 0x7fff1225efb8 --> 0x7fff122611fd --> 0x736c2f6e69622f ('/bin/ls')
0024| 0x7fff1225eef0 --> 0x100000000 
0032| 0x7fff1225eef8 --> 0x402a00 (push   r15)
0040| 0x7fff1225ef00 --> 0x0 
0048| 0x7fff1225ef08 --> 0xdeca45a1d59f8b89 
0056| 0x7fff1225ef10 --> 0x4049a0 (xor    ebp,ebp)
0064| 0x7fff1225ef18 --> 0x7fff1225efb0 --> 0x1 
0072| 0x7fff1225ef20 --> 0x0
gdb-peda$ context reg


 [----------------------------------registers-----------------------------------]
RAX: 0x402a00 (push   r15)
RBX: 0x0 
RCX: 0x0 
RDX: 0x7fff1225efc8 --> 0x7fff12261205 ("LC_PAPER=ro_RO.UTF-8")
RSI: 0x7fff1225efb8 --> 0x7fff122611fd --> 0x736c2f6e69622f ('/bin/ls')
RDI: 0x1 
RBP: 0x413be0 (push   r15)
RSP: 0x7fff1225eed8 --> 0x7fb93f6b9830 (<__libc_start_main+240>:	mov    edi,eax)
RIP: 0x402a00 (push   r15)
R8 : 0x413c50 (repz ret)
R9 : 0x7fb93fc948e0 (<_dl_fini>:	push   rbp)
R10: 0x846 
R11: 0x7fb93f6b9740 (<__libc_start_main>:	push   r14)
R12: 0x4049a0 (xor    ebp,ebp)
R13: 0x7fff1225efb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
{% endhighlight nasm %}

## radare2

{% highlight nasm %}
[0x00402a00]> pxr @ rsp!80
0x7ffe4ea90fb8  0x00007fc0a5275830   0X'..... (/lib/x86_64-linux-gnu/libc-2.23.so) library R X 'mov edi, eax' 'libc-2.23.so'
0x7ffe4ea90fc0  0x0000000000000000   ........ r15
0x7ffe4ea90fc8  0x00007ffe4ea91098   ...N.... rsi stack R W 0x7ffe4ea931a0 --> stack R W 0x736c2f6e69622f (/bin/ls) --> ascii
0x7ffe4ea90fd0  0x0000000100000000   ........
0x7ffe4ea90fd8  0x0000000000402a00   .*@..... (.text) (/bin/ls) rip program ascii R X 'push r15' 'ls'
0x7ffe4ea90fe0  0x0000000000000000   ........ r15
0x7ffe4ea90fe8  0xd73cce5c2543d7a1   ..C%\.<.
0x7ffe4ea90ff0  0x00000000004049a0   .I@..... (.text) (/bin/ls) r12 program R X 'xor ebp, ebp' 'ls'
0x7ffe4ea90ff8  0x00007ffe4ea91090   ...N.... r13 stack R W 0x1 --> (.gnu_debuglink) rdi
0x7ffe4ea91000  0x0000000000000000   ........ r15
[0x00402a00]> drr
  orax 0xffffffffffffffff  orax
   rax 0x0000000000402a00  (.text) (/bin/ls) rip program ascii R X 'push r15' 'ls'
   rbx 0x0000000000000000  r15
   rcx 0x0000000000000000  r15
   rdx 0x00007ffe4ea910a8  rdx stack R W 0x7ffe4ea931a8 --> stack R W 0x524e54565f474458 (XDG_VTNR=7) --> ascii
    r8 0x0000000000413c50  (.text) (/bin/ls) r8 program ascii R X 'ret' 'ls'
    r9 0x00007fc0a58508e0  (/lib/x86_64-linux-gnu/ld-2.23.so) r9 library R X 'push rbp' 'ld-2.23.so'
   r10 0x0000000000000846  r10
   r11 0x00007fc0a5275740  (/lib/x86_64-linux-gnu/libc-2.23.so) r11 library R X 'push r14' 'libc-2.23.so'
   r12 0x00000000004049a0  (.text) (/bin/ls) r12 program R X 'xor ebp, ebp' 'ls'
   r13 0x00007ffe4ea91090  r13 stack R W 0x1 --> (.gnu_debuglink) rdi
   r14 0x0000000000000000  r15
   r15 0x0000000000000000  r15
   rsi 0x00007ffe4ea91098  rsi stack R W 0x7ffe4ea931a0 --> stack R W 0x736c2f6e69622f (/bin/ls) --> ascii
   rdi 0x0000000000000001  (.gnu_debuglink) rdi
   rsp 0x00007ffe4ea90fb8  rsp stack R W 0x7fc0a5275830 --> (/lib/x86_64-linux-gnu/libc-2.23.so) library R X 'mov edi, eax' 'libc-2.23.so'
   rbp 0x0000000000413be0  (.text) (/bin/ls) rbp program R X 'push r15' 'ls'
   rip 0x0000000000402a00  (.text) (/bin/ls) rip program ascii R X 'push r15' 'ls'
rflags 0x0000000000000246  rflags
{% endhighlight nasm %}

# Breakpoint commands

## PEDA

```
gdb-peda$ commands 1
gdb-peda$ commands 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>set $rax=0xdeadbeef
>set $rbx=0xdeadc0de
>end
gdb-peda$ i b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000402a00 
	breakpoint already hit 1 time
        set $rax=0xdeadbeef
        set $rbx=0xdeadc0de
```

## radare2

Warning: some commands may not work properly with `dbc`.

{% highlight nasm %}
[0x7fcd2c7a2cc0]> "dbc main pi 10;pxr@rsp!8;ps @ 0x0041a5f6"
[0x7fcd2c7a2cc0]> dc
= attach 5283 1
hit breakpoint at: 402a00
  

mov rdi, rsp
call 0x7fcd2c7a6c00
mov r12, rax
mov eax, dword [rip + 0x224fa7]
pop rdx
lea rsp, [rsp + rax*8]
sub edx, eax
push rdx
mov rsi, rdx
mov r13, rsp
0x7ffffe8da290  0x0000000000000001   ........ (.gnu_debuglink)
CHARSETALIASDIR
{% endhighlight nasm %}

# Closing remarks

Radare2 also has numerous features which PEDA lacks, such as CFG, heap analysis, renaming variables and arguments in the disassembly and many more. One thing which r2 is missing is a nice [pwntools](https://github.com/Gallopsled/pwntools) integration (although I think this can be easily done on the fly by attaching r2 to the running process. r2pipe + pwntools, however, would be a different story).

Still feel like missing something? Drop [me](https://twitter.com/monosrc) a line or ask on #radare on freenode.
