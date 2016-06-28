---
layout: post
title: "Solving Radare2 Explorations Tutorial 2 with angr"
date: 2016-06-28 10:25:06
description: A very short intro to angr and symbolic execution
tags:
 - symbolic execution
 - angr
share: true
---

# Context

I've been looking into symbolic execution lately and, more specifically, [angr](http://angr.io/), a binary analysis framework which is also capable of symbolically executing binaries.

# So what's all this "symbolic" execution about?

It's simpler to explain visually. Suppose we have the following simple C program:

{% highlight c %}
#include <stdio.h>

int main(int argc, char* argv[])
{
	int x = 0;

	scanf("%d", &x);

	if (x % 2 == 0)
		printf ("x is even\n");
	else
		printf ("x is odd\n");

	return 0;
}
{% endhighlight c %}

When executing this program, after the user supplies the value of `x` (i.e. 5), it is set in stone from that point on (or until the program ends or changes the value of `x` somehow). We say that `x` has a *concrete* value. Since `x` is fixed, we can safely say that the program will only run through one of the two possible paths.

Symbolic execution allows for variables, registers, memory regions and even file descriptors to be *symbolic*. This means that in a symbolic context, `x` is no longer the (concrete) value supplied by the user, but rather a symbolic value. This new type of value will reach the `if` statement which will trigger the symbolic execution engine to *fork* on two different paths: one in which `x % 2 == 0` holds true (`x` still being symbolic, and the entire expression as well) and one in which the negation holds true. This way, the engine explores all possible paths of the program.

As the paths are explored, symbolic expressions are built and constraints are added to the forked states. These constraints can then be passed on to an SMT solver like [Z3](https://github.com/Z3Prover/z3) which will determine a *concrete* value which satisfies said constraints.

# How does this help me in a practical way?

Think of a program which requires a valid input to grant you access to some file or network. A program can be seen as a complex graph of basic blocks of code. This graph most likely has a "start" node, a "success" node and a "failure" node, among many other intermediate nodes. You want to find the answer to the question: how do I get from the "start" node to the "success" node while avoiding the "failure" node? The answer to your question can be given through symbolic execution.

There are practical limitations to symbolic execution, such as path explosion, which won't be discussed in this post.

# Example

We'll use the binary from [tutorial 2](https://github.com/monosource/radare2-explorations-binaries/tree/master/tut2-memory) from [Radare2 Explorations](https://monosource.gitbooks.io/radare2-explorations/content/).

{% highlight bash %}
$ ./xor
Enter the password: 1234
Wrong!
{% endhighlight bash %}

Let's have a look at the internals of this binary using radare2.

{% highlight nasm %}
╒ (fcn) sym.main 256
│           ---------------CUT--------------------
│           0x08048440      6880860408     push str.Enter_the_password: ; str.Enter_the_password: ; "Enter the password: " @ 0x8048680
│           0x0804845d      e8eefeffff     call sym.imp.printf
│           0x08048462      58             pop eax
│           0x08048463      5a             pop edx
│           0x08048464      57             push edi
│           0x08048465      6895860408     push str._32s ; str._32s    ; "%32s" @ 0x8048695
│           0x0804846a      e821ffffff     call sym.imp.__isoc99_scanf
│           0x0804846f      59             pop ecx
│           0x08048470      58             pop eax
│           0x08048471      8d45d7         lea eax, [ebp - local_29h]
│           0x08048474      50             push eax
│           0x08048475      57             push edi
│           0x08048476      e835010000     call sym.check
│           0x0804847b      83c410         add esp, 0x10
│           0x0804847e      85c0           test eax, eax
│       ┌─< 0x08048480      741c           je 0x804849e
│       │   0x08048482      83ec0c         sub esp, 0xc
│       │   0x08048485      68a1860408     push str.Good_job__:_ ; str.Good_job__:_ ; "Good job! :)" @ 0x80486a1
│       │   0x0804848a      e8d1feffff     call sym.imp.puts
│       │   0x0804848f      83c410         add esp, 0x10
│       │   ; JMP XREF from 0x080484ae (sym.main)
│      ┌──> 0x08048492      8d65f8         lea esp, [ebp - local_8h]
│      ││   0x08048495      31c0           xor eax, eax
│      ││   0x08048497      59             pop ecx
│      ││   0x08048498      5f             pop edi
│      ││   0x08048499      5d             pop ebp
│      ││   0x0804849a      8d61fc         lea esp, [ecx - 4]
│      ││   0x0804849d      c3             ret
│      ││   ; JMP XREF from 0x08048480 (sym.main)
│      │└─> 0x0804849e      83ec0c         sub esp, 0xc
│      │    0x080484a1      689a860408     push str.Wrong_ ; str.Wrong_ ; "Wrong!" @ 0x804869a
│      │    0x080484a6      e8b5feffff     call sym.imp.puts
│      │    0x080484ab      83c410         add esp, 0x10
╘      └──< 0x080484ae      ebe2           jmp 0x8048492
{% endhighlight nasm %}

The program seems fairly simple. It reads a password from stdin, calls the `sym.check` function, and then prints "Good job! :)" or "Wrong!" depending on the result of the verification.

We're going to solve this blindly. `angr` is going to do all of the work for us.We don't even care what the check function does. We just need to tell `angr` that we want an input which gets us at `0x08048485`, which is our "success" state, and avoid `0x080484a1`, which is our "failure" state.

{% highlight python %}
import angr

def main():
    p = angr.Project("./xor", load_options={'auto_load_libs': False})
	ex = p.surveyors.Explorer(find=(0x08048485,), avoid=(0x080484a1,))
	ex.run()

	return ex.found[0].state.posix.dumps(0).strip('\0\n')

if __name__=='__main__':
	print main()

{% endhighlight python %}

Let's see how well it does.

{% highlight bash %}
$ time python solve.py 
MONO[th4t_wa5~pr3tty=ea5y_r1gh7]

real	0m2.210s
user	0m2.084s
sys	0m0.104s
$ ./xor 
Enter the password: MONO[th4t_wa5~pr3tty=ea5y_r1gh7]
Good job! :)
{% endhighlight bash %}

Almost feels like cheating, doesn't it?

Have fun with angr in your future endeavors!
