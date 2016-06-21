---
layout: post
title: "Solving CMU Binary Bomb Phase 2 (the smug way)"
date: 2016-06-20 10:25:06
description: CMU Binary Bomb Phase 2 Solution using Radare2
tags:
 - radare2
 - reversing
share: true
---

# Context

In this post, I will cover a dynamic solution for the second phase of the [CMU Binary Bomb](https://csapp.cs.cmu.edu/3e/bomb.tar), which is a lot of fun and teaches you how some C basics, such as switch statements, recursion, linked lists, end up as assembly.

# Phase 2 of the Bomb

Although this phase can easily be [done by hand](https://unlogic.co.uk/2016/04/20/binary-bomb-with-radare2-phase-2/), or [symbolic execution](http://ctfhacker.com/ctf/python/symbolic/execution/reverse/radare/2015/11/28/cmu-binary-bomb-flag2.html), the solution I will be presenting can be easily adapted for more complex tasks.

We'll start by loading the binary in radare2, in debug mode.

{% highlight bash %}
$ r2 -Ad bomb
{% endhighlight bash %}

We'll continue until `sym.phase_2`

{% highlight raw %}
[0xf76fbd00]> dcu sym.phase_2
{% endhighlight raw %}

I'll not spoil the solution for `phase_1`, even though it's fairly easy to get to it.

If we look at the code of `phase_2`, we'll notice that it reads six numbers and then compares them with some values in a loop.

{% highlight raw %}
╒ (fcn) sym.phase_2 79
│           ; var int local_28h @ ebp-0x28
│           ; var int local_18h @ ebp-0x18
│           ; arg int arg_1h @ ebp+0x1
│           ; arg int arg_8h @ ebp+0x8
│           ; CALL XREF from 0x08048a7e (sym.main)
│           0x08048b48      55             push ebp
│           0x08048b49      89e5           mov ebp, esp
│           0x08048b4b      83ec20         sub esp, 0x20
│           0x08048b4e      56             push esi
│           0x08048b4f      53             push ebx
│           0x08048b50      8b5508         mov edx, dword [ebp + arg_8h] ; [0x8:4]=-1 ; 8
│           0x08048b53      83c4f8         add esp, -8
│           0x08048b56      8d45e8         lea eax, [ebp - local_18h]
│           0x08048b59      50             push eax
│           0x08048b5a      52             push edx
│           0x08048b5b      e878040000     call sym.read_six_numbers
│           0x08048b60      83c410         add esp, 0x10
│           0x08048b63      837de801       cmp dword [ebp - local_18h], 1 ; [0x1:4]=-1 ; 1
│       ┌─< 0x08048b67      7405           je 0x8048b6e
│       │   0x08048b69      e88e090000     call sym.explode_bomb
│       └─> 0x08048b6e      bb01000000     mov ebx, 1
│           0x08048b73      8d75e8         lea esi, [ebp - local_18h]
│       ┌─> 0x08048b76      8d4301         lea eax, [ebx + 1]          ; 0x1 ; 1
│       │   0x08048b79      0faf449efc     imul eax, dword [esi + ebx*4 - 4]
│       │   0x08048b7e      39049e         cmp dword [esi + ebx*4], eax ; [0x13:4]=-1 ; 19
│      ┌──< 0x08048b81      7405           je 0x8048b88
│      ││   0x08048b83      e874090000     call sym.explode_bomb
│      └──> 0x08048b88      43             inc ebx
│       │   0x08048b89      83fb05         cmp ebx, 5                  ; 5
│       └─< 0x08048b8c      7ee8           jle 0x8048b76
│           0x08048b8e      8d65d8         lea esp, [ebp - local_28h]
│           0x08048b91      5b             pop ebx
│           0x08048b92      5e             pop esi
│           0x08048b93      89ec           mov esp, ebp
│           0x08048b95      5d             pop ebp
╘           0x08048b96      c3             ret
{% endhighlight raw %}

We're going to make this phase solve itself, because we're too ~~lazy~~ smart to do any manual work (or any work, for that matter).

# Go Solve Yourself

We're going to set two breakpoints. One at the `cmp` instruction within the loop, at `0x8048b7e`, and one right after the loop, at `0x8048b8e`.

{% highlight raw %}
[0x08048b48]> db 0x8048b7e
[0x08048b48]> db 0x8048b8e
[0x08048b48]> db
0x08048b7e - 0x08048b7f 1 --x sw break enabled cmd="" name="0x8048b7e" module=""
0x08048b8e - 0x08048b8f 1 --x sw break enabled cmd="" name="0x8048b8e" module=""
{% endhighlight raw %}

Now comes the fun part. In radare2, you can add commands to be executed whenever a breakpoint is hit via `dbc`. We'll force our values, which reside at `esi + ebx*4` to always be equal to the value in `eax`.

{% highlight raw %}
[0x08048b48]> "dbc 0x8048b7e .dr*;*(esi+ebx*4)=`dr eax`"
[0x08048b48]> "dbc 0x8048b8e pf dddddd @ esi"
[0x08048b48]> db
0x08048b7e - 0x08048b7f 1 --x sw break enabled cmd=".dr*;*(esi+ebx*4)=`dr eax`" name="0x8048b7e" module=""
0x08048b8e - 0x08048b8f 1 --x sw break enabled cmd="pf dddddd @ esi" name="0x8048b8e" module=""
{% endhighlight raw %}

The first `dbc` statement adds two commands to be executed whenever the breakpoint at `cmp` is hit. `.dr*` executes `dr*` as radare2 commands, to force "sync" the registers when the breakpoint is hit.
`` *(esi+ebx*4)=`dr eax` `` writes at `esi + ebx*4` (our input) the value of `eax` (the desired value). Thus, the comparison will always be true until the loop ends.

The second `dbc` statement prints the resulting `esi` at the end of the loop, which will be the valid input for defusing this phase of the bomb.

There is one last element that is out of place: execution will still break inside the loop at every iteration. We want our commands to be executed at that point, but without breaking. We can set this breakpoint to be a tracepoint instead.

{% highlight raw %}
[0x08048b48]> dbte 0x8048b7e
[0x08048b48]> db
0x08048b7e - 0x08048b7f 1 --x sw trace enabled cmd=".dr*;*(esi+ebx*4)=`dr eax`" name="0x8048b7e" module=""
0x08048b8e - 0x08048b8f 1 --x sw break enabled cmd="pf dddddd @ esi" name="0x8048b8e" module=""
{% endhighlight raw %}

Now we should be set. Just `dc` and enjoy.

{% highlight raw %}
[0x08048b4b]> dc
hit tracepoit at: 8048b7e
fs+regs
fs-
hit breakpoint at: 8048b81
hit tracepoit at: 8048b7e
fs+regs
fs-
hit breakpoint at: 8048b81
hit tracepoit at: 8048b7e
fs+regs
fs-
hit breakpoint at: 8048b81
hit tracepoit at: 8048b7e
fs+regs
fs-
hit breakpoint at: 8048b81
hit tracepoit at: 8048b7e
fs+regs
fs-
hit breakpoint at: 8048b81
hit breakpoint at: 8048b8e

0xff9aa630 = 1
0xff9aa634 = 2
0xff9aa638 = 6
0xff9aa63c = 24
0xff9aa640 = 120
0xff9aa644 = 720
{% endhighlight raw %}

We're done with this phase. Those are the defusal numbers.

Hope you've enjoyed reading. Have fun with the bomb!
