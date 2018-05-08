---
layout: post
title: "TrendMicro CTF 2016 - re100"
date: 2016-08-03 00:25:06
description: Solving a reverse engineering challenge using r2 and ESIL
categories:
 - writeup
tags:
 - radare2
share: true
---

# Context

The [TrendMicro CTF](https://ctf.trendmicro.co.jp) was a blast (apart for some Shakespeare guesswork), and I solved a challenge using radare2, so I thought this would be a good opportunity to present a challenge which can be solved using emulation.

# The challenge

[Link](http://www.mediafire.com/download/n7gt2ry237578co/files13.zip)

We're provided with a file called `dataloss`.

{% highlight bash %}
$ file dataloss
dataloss: data
{% endhighlight bash %}

OK, so `file` doesn't know what it is. Time to open it in radare2.

{% highlight bash %}
$ r2 -b 32 -a x86 dataloss
{% endhighlight bash %}

If we look around in visual mode, we can see that some instructions make sense. We can tell r2 to auto-analyze the data and identify functions.

{% highlight nasm %}
[0x00000000]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
[0x00000000]> afl | wc -l
379
{% endhighlight nasm %}

Plenty of functions found. We can switch to visual mode and cycle through them using `n/N`. Most of them look like garbage, until we stumble upon the following:

{% highlight nasm %}
[0x00000278]> pdf
╒ (fcn) fcn.00000278 492
│           ; var int local_24h @ ebp-0x24
│           ; var int local_23h @ ebp-0x23
│           ; var int local_1fh @ ebp-0x1f
│           ; var int local_1bh @ ebp-0x1b
│           ; var int local_17h @ ebp-0x17
│           ; var int local_13h @ ebp-0x13
│           ; var int local_fh @ ebp-0xf
│           ; var int local_bh @ ebp-0xb
│           ; var int local_7h @ ebp-0x7
│           ; var int local_4h @ ebp-0x4
│           ; arg int arg_8h @ ebp+0x8
│           ; CALL XREF from 0x0000046f (fcn.00000468)
│           0x00000278      55             push ebp
│           0x00000279      8bec           mov ebp, esp
│           0x0000027b      83ec24         sub esp, 0x24
│           0x0000027e      c645dc00       mov byte [ebp - local_24h], 0
│           0x00000282      33c0           xor eax, eax
│           0x00000284      8945dd         mov dword [ebp - local_23h], eax
│           0x00000287      8945e1         mov dword [ebp - local_1fh], eax
│           0x0000028a      8945e5         mov dword [ebp - local_1bh], eax
│           0x0000028d      8945e9         mov dword [ebp - local_17h], eax
│           0x00000290      8945ed         mov dword [ebp - local_13h], eax
│           0x00000293      8945f1         mov dword [ebp - local_fh], eax
│           0x00000296      8945f5         mov dword [ebp - local_bh], eax
│           0x00000299      8845f9         mov byte [ebp - local_7h], al
│           0x0000029c      8b4d08         mov ecx, dword [ebp + arg_8h] ; [0x8:4]=0
│           0x0000029f      83c14b         add ecx, 0x4b
│           ---------------------------- SNIP ----------------------------
│           0x00000460      8be5           mov esp, ebp
│           0x00000462      5d             pop ebp
╘           0x00000463      c3             ret
{% endhighlight nasm %}

It has a single argument, which it loads in the `ecx` register, and then it moves all sorts of hardcoded values onto the stack. There are two directions we can go from here:

1. Dump this function into an assembly source file, call it from main, assemble the file and run it in a debugger.
2. ESIL.

We'll obviously go with the second option, since it's faster.

ESIL will need to perform some writes in memory, and since we opened the file in read-only mode, we're going to need to enable caching. Then we will initialize the ESIL VM. All ESIL-related commands are preceded by `ae`. You can view them by inputing `ae?`

{% highlight nasm %}
[0x00000278]> ae?
|Usage: ae[idesr?] [arg]ESIL code emulation
| ae?                show this help
| ae??               show ESIL help
| aei                initialize ESIL VM state (aei- to deinitialize)
| aeim               initialize ESIL VM stack (aeim- remove)
| aeip               initialize ESIL program counter to curseek
| ae [expr]          evaluate ESIL expression
| aex [hex]          evaluate opcode expression
| ae[aA][f] [count]  analyse esil accesses (regs, mem..)
| aep [addr]         change esil PC to this address
| aef [addr]         emulate function
| aek [query]        perform sdb query on ESIL.info
| aek-               resets the ESIL.info sdb instance
| aec                continue until ^C
| aecs [sn]          continue until syscall number
| aecu [addr]        continue until address
| aecue [esil]       continue until esil expression match
| aetr[esil]         Convert an ESIL Expression to REIL
| aes                perform emulated debugger step
| aeso               step over
| aesu [addr]        step until given address
| aesue [esil]       step until esil expression match
| aer [..]           handle ESIL registers like 'ar' or 'dr' does
[0x00000278]> e io.cache = true
[0x00000278]> aei               # initialize VM
[0x00000278]> aeim              # initialize memory/stack
[0x00000278]> aeip              # set EIP to current offset
{% endhighlight nasm %}

Now we can emulate the function by stepping until `0x00000460` and print `ebp` at that point.

{% highlight nasm %}
[0x00000278]> aesu 0x460
ADDR BREAK
[0x00000447]> ps @ ebp - 0x24
KD:K=r[XkXcfjjnfekjkfgljt
{% endhighlight nasm %}

Hmm, this doesn't look like a flag. Luckily, we know what the flag should look like: `TMCTF{...}`. Remember that this function receives an argument, which is assigned to `ecx`. Then, the value `0x4b`, corresponding to the letter `K` is added to it. We can figure out that `ecx` needs to be the value `0x9` in order to get `T` as the first letter of the flag.

Let's rewind a bit and set the argument for our function at `ebp+0x8` to `0x9`.

{% highlight nasm %}
[0x0000027e]> s 0x278
[0x00000278]> aeim-
Deinitialized mem.0x100000_0xf0000
[0x00000278]> aei-
[0x00000278]> aei
[0x00000278]> aeim
[0x00000278]> aeip
[0x00000278]> 13aes             # step 13 times
[0x00000278]> *(ebp+0x8) = 0x9  # set function argument to 9
[0x00000278]> aesu 0x460        # step until right before cleaning the stack frame
ADDR BREAK
[0x00000447]> ps @ ebp-0x24
TMCTF{datalosswontstopus}
{% endhighlight nasm %}

And there's our flag!
