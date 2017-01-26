---
layout: post
title: "Binary instrumentation with Frida on Linux (Part 1)"
date: 2017-01-26 00:25:06
description: A short introduction to instrumentation and Frida on Linux
tags:
 - frida
 - instrumentation
share: true
---

With the recent release of [Frida version 9](https://www.frida.re/news/2017/01/09/frida-9-0-released/), I got motivated to dive into it some more and figure things out by myself, since the [Linux](https://www.frida.re/docs/examples/linux/) section is disappointingly dry at the moment.

## Dynamic Binary Instrumentation

DBI is a runtime analysis technique for code, be it source or binary. You usually come across it in relation to code profiling done in order to optimize performance or find memory leaks.

The principle behind instrumentation is that of injecting your own code to run inside a given process. In layman's terms, the main difference in principle between instrumenting and debugging is that with a debugger you attach to a process; with instrumentation, you **are** the process (in some sense).

## Illustrative example

Consider the following code:

{% highlight nasm %}
push rbp
mov rbp, rsp
sub rsp, 0x20
mov dword [rbp - 0x14], edi
mov qword [rbp - 0x20], rsi
mov edi, 1
call sym.imp.malloc
mov qword [rbp - 8], rax
mov rax, qword [rbp - 8]
mov rdi, rax
call sym.imp.free
mov eax, 0
leave
ret
{% endhighlight nasm %}

We wish to instrument the `malloc` and `free` instructions by inserting our own code. We obviously cannot do this in the .text segment. The interpreter will map its own region of memory in which it can both write and execute code. It will then make a copy of the original code and add our own, as follows:

{% highlight nasm %}
malloc:
<save registers>
call on_enter_malloc_callback
<restore registers>
push rbp
mov rbp, rsp
<rest of malloc code>
<save registers>
call on_leave_malloc_callback
<restore registers>
ret
{% endhighlight nasm %}

In this way, whenever `malloc` is called, it will in turn call our instrumentation routine, which can print the argument (or change it!), or the return value, or increment a counter, print the register values at that point and so on. Much more complex things can be achieved, such as passing a custom `sockaddr_in` struct to a `connect` call.

This technique is known as interception. Instruction level instrumentation is the fine-grained version in which each instruction is instrumented, rather than each function.

## Use cases

As mentioned previously, **profiling** and tracking down leaks (the [Valgrind](http://valgrind.org/) suite is a good example for this). But there are other interesting use-cases as well, such as **fault injection**, **reversing/discovering APIs**, building **code tracers**, **side-channel attacks** on badly implemented crypto binaries (i.e. via counting instructions), **fuzzing** and **taint analysis**.

## Frameworks

Two very efficient and feature-rich instrumentation frameworks are [Intel's Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) and [DynamoRIO](http://www.dynamorio.org/). Both of them provide a C/C++ API in which you can write your instrumentation code. You then have to compile your code into a dynamic library which will be injected in the desired binary.

## Frida

The third option is the relatively recent but fast-growing Frida framework. There are a couple of advantages (or disadvantages, depending on how you look at it). Frida injects a JavaScript interpreter (Duktape by default as of version 9; it's capable of also injecting the bulkier Google V8 engine) inside the binary, which is capable of running JS code. Now, instead of writing C code, you're writing JS to instrument your binary. This also means that you don't have to compile anything. Frida always injects the same interpreter; what gets changed is the instrumentation code written in JavaScript. In effect, you are manipulating low-level elements (basic blocks, instructions) using a high-level language.

Frida is a good excuse for a reverse engineer to learn a bit of JavaScript, or for a web developer to learn a bit of reversing. Being in the former case, I stumbled across the wonderful world of JS, where every Number is a Float, where the *triple equals* operator exists (and is needed; and I heard of a *quad* equals operator being requested) and where very [interesting](https://gist.github.com/MichalZalecki/c964192f830360ce6361) (in the most frustrating sense imaginable) things happen.

The comprehensive [JS API](https://www.frida.re/docs/javascript-api/) features some very high-level entities, such as ObjC and Java, which allow for access to native ObjectiveC and Java methods and objects, which are brilliant to use when working with mobile platforms like Android and iOS.

While the instrumentation code has to be written in JavaScript, the resulting tools can be written in either Python or JS. The injected interpreter can communicate with your application via primitive `send` and `recv` methods. The data exchanged has to be serializable to JSON.

## The REPL

After installing the framework and Python bindings (which is a breeze via pip), you get a collection of tools which have been built using Frida, such as the REPL, frida-discover, frida-ls-devices, frida-ps, frida-trace.

Just like with a debugger, you can use the Frida CLI app to attach to a process or spawn a new one.

{% highlight bash %}
$ frida ./cli_example
     ____
    / _  |   Frida 9.0.13 - A world-class dynamic instrumentation framework
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Spawned `./cli_example`. Use %resume to let the main thread start executing!
[Local::file::[u'./cli_example']]-> 
{% endhighlight bash %}

We're given a fully fledged, beautifully-colored JS REPL, much like iPython, inside the binary. What's lacking as of now is an interactive help, but that's what the JS API Docs are for.

We can explore the binary a little, by enumerating function names from imports, getting addresses from debug symbols (won't work on stripped binaries, obviously), disassemble an instruction at an address.

{% highlight javascript %}
[Local::file::[u'./cli_example']]-> Module.enumerateImportsSync('cli_example').forEach( function (elem) { console.log(elem['name']); });
AES_set_encrypt_key
__libc_start_main
AES_encrypt
AES_decrypt
AES_set_decrypt_key
__stack_chk_fail
[Local::file::[u'./cli_example']]-> DebugSymbol.fromName('main')
{
    "address": "0x4007a4",
    "fileName": "",
    "lineNumber": 0,
    "moduleName": "cli_example",
    "name": "main"
}
[Local::file::[u'./cli_example']]-> DebugSymbol.fromName('cooky_math')
{
    "address": "0x400776",
    "fileName": "",
    "lineNumber": 0,
    "moduleName": "cli_example",
    "name": "cooky_math"
}
[Local::file::[u'./cli_example']]-> Instruction.parse(ptr(DebugSymbol.fromName('main')['address']));
{
    "address": "0x4007a4",
    "mnemonic": "push",
    "next": "0x4007a5",
    "opStr": "rbp",
    "size": 1
}
[Local::file::[u'./cli_example']]-> Instruction.parse(ptr(DebugSymbol.fromName('main')['address'])).toString();
"push rbp"
{% endhighlight javascript %}

Let's build on that last example to disassemble the main function.

{% highlight javascript %}
[Local::file::[u'./cli_example']]-> var cinstr = ''; // Initialize current instruction
""
[Local::file::[u'./cli_example']]-> var pc = ptr(DebugSymbol.fromName('main')['address']); // Initialize simulated pc
"0x4007a4"
[Local::file::[u'./cli_example']]-> while (cinstr.indexOf('ret') === -1) { instr = Instruction.parse(pc); cinstr = instr.toString(); caddr = instr['address']; console.log(caddr + " " + cinstr); pc = ptr(instr['next']); }
0x4007a4 push rbp
0x4007a5 mov rbp, rsp
0x4007a8 sub rsp, 0x2d0
0x4007af mov dword ptr [rbp - 0x2c4], edi
====================SNIP====================
0x400885 ret 
{% endhighlight javascript %}

## Moving on to scripting

That last example was a little extreme for CLI use. We can use it as a building block for a simple disassembly tool. Please note that I like to keep my instrumentation JS code and my Python management code in separate script files.

First, the code which performs the actual disassembly.

{% highlight javascript %}
cinstr = '';
// Format string to be used in Python
pc = ptr("%s")
while (cinstr.indexOf('ret') === -1) {
	instr = Instruction.parse(pc);
	caddr = instr['address'];
	cinstr = instr.toString();
	console.log(caddr + " " + cinstr);
	pc = ptr(instr['next'])
}
{% endhighlight javascript %}

This script will receive an address in hex from the Python script, which will in turn be given as a command-line argument.

Next, the management code, pretty easy to read and understand.
{% highlight python %}
#!/usr/bin/env python
import frida
import sys

if len(sys.argv) != 2:
    print 'Usage: ' + sys.argv[0] + ' <address>'
    sys.exit(1)

# Spawn and attach to process
pid = frida.spawn(['./cli_example'])
session = frida.attach(pid)

# Read the instrumentation script
contents = open('dis.js').read()
script = session.create_script(contents % int(sys.argv[1], 16))

# Pass it to the injected interpreter
script.load()
{% endhighlight python %}

Now we can test it.

{% highlight bash %}
$ ./disas.py 0x00400766
0x400766 push rbp
0x400767 mov rbp, rsp
0x40076a mov dword ptr [rbp - 4], edi
0x40076d mov eax, dword ptr [rbp - 4]
0x400770 imul eax, dword ptr [rbp - 4]
0x400774 pop rbp
0x400775 ret 
{% endhighlight bash %}

Brilliant!

## Building our own ltrace

Let's use Frida's `Interceptor` to trace all `malloc` and `free` calls performed by a binary, similar to `ltrace`. We want to know how much is being requested to be allocated, pointer values returned and the argument of free.

{% highlight bash %}
$ ltrace -e malloc+free ./mallocs > /dev/null
mallocs->malloc(80)                                                                     = 0x1d54010
mallocs->malloc(32)                                                                     = 0x1d54070
mallocs->malloc(32)                                                                     = 0x1d540a0
mallocs->malloc(32)                                                                     = 0x1d540d0
mallocs->malloc(32)                                                                     = 0x1d54100
mallocs->malloc(32)                                                                     = 0x1d54130
mallocs->malloc(32)                                                                     = 0x1d54160
mallocs->malloc(32)                                                                     = 0x1d54190
mallocs->malloc(32)                                                                     = 0x1d541c0
mallocs->malloc(32)                                                                     = 0x1d541f0
mallocs->malloc(32)                                                                     = 0x1d54220
mallocs->free(0x1d54070)                                                                = <void>
mallocs->free(0x1d540a0)                                                                = <void>
mallocs->free(0x1d540d0)                                                                = <void>
mallocs->free(0x1d54100)                                                                = <void>
mallocs->free(0x1d54130)                                                                = <void>
mallocs->free(0x1d54160)                                                                = <void>
mallocs->free(0x1d54190)                                                                = <void>
mallocs->free(0x1d541c0)                                                                = <void>
mallocs->free(0x1d541f0)                                                                = <void>
mallocs->free(0x1d54220)                                                                = <void>
mallocs->free(0x1d54010)                                                                = <void>
+++ exited (status 0) +++
{% endhighlight bash %}

We'll be using pretty much the same Python script, but do note the `frida.resume(pid)` to get the process to resume execution.

{% highlight python %}
#!/usr/bin/env python
import frida
import sys

pid = frida.spawn(['./mallocs'])
session = frida.attach(pid)

contents = open('malloc_free.js').read()
script = session.create_script(contents)
script.load()
frida.resume(pid)
sys.stdin.read()
{% endhighlight python %}

Frida's `Interceptor` can auto-detect some of the common calling conventions. If this wasn't the case, then we could simply use the global `context` to read registers, or navigate through memory to retrieve the arguments.

{% highlight javascript %}
console.log('Tracing initiated');
// Interceptor's first argument is a NativePointer to which it attaches.
// The second argument is a list of callbacks (i.e. what to do at a certain event, such as entering or leaving the function).
Interceptor.attach(Module.findExportByName(null, 'malloc'),
		{
			// When entering malloc, print its argument as an integer to the console.
			onEnter: function (args) {
				console.log("malloc(" + args[0].toInt32() + ")");
			},
			// When returning from malloc, print the return value (pointer) as a hexadecimal string.
			onLeave: function (retval) {
				console.log("-> 0x" + retval.toString(16));
			}
		});

// We need a second Interceptor for 'free'
Interceptor.attach(Module.findExportByName(null, 'free'),
		{
			onEnter: function (args) {
				console.log("free(0x" + args[0].toString(16) + ")");
			}
		});
{% endhighlight javascript %}

And that's about it. Let's see if this works.

{% highlight bash %}
$ ./trace.py 
Tracing initiated
malloc(80)
-> 0x12c2840
malloc(32)
-> 0x12c28a0
malloc(32)
-> 0x12c28d0
malloc(32)
-> 0x12c2900
malloc(32)
-> 0x12c2930
malloc(32)
-> 0x12c2960
malloc(32)
-> 0x12c2990
malloc(32)
-> 0x12c29c0
malloc(32)
-> 0x12c29f0
malloc(32)
-> 0x12c2a20
malloc(32)
-> 0x12c2a50
free(0x12c28a0)
free(0x12c28d0)
free(0x12c2900)
free(0x12c2930)
free(0x12c2960)
free(0x12c2990)
free(0x12c29c0)
free(0x12c29f0)
free(0x12c2a20)
free(0x12c2a50)
free(0x12c2840)
{% endhighlight bash %}

## frida-trace

Let's redo the last example using `frida-trace`, a nifty tracer built using Frida.

{% highlight bash %}
$ frida-trace -i malloc -i free ./mallocs
Instrumenting functions...                                              
malloc: Auto-generated handler at "/__handlers__/libc_2.23.so/malloc.js"
malloc: Auto-generated handler at "/__handlers__/ld_2.23.so/malloc.js"
free: Auto-generated handler at "/__handlers__/libc_2.23.so/free.js"
free: Auto-generated handler at "/__handlers__/ld_2.23.so/free.js"
Started tracing 4 functions. Press Ctrl+C to stop.                      
           /* TID 0x5cd1 */
   183 ms  malloc()
   184 ms  malloc()
   184 ms  malloc()
   184 ms  malloc()
   184 ms  malloc()
   184 ms  malloc()
   184 ms  malloc()
   185 ms  malloc()
   185 ms  malloc()
   185 ms  malloc()
   185 ms  malloc()
   185 ms  malloc()
   186 ms  free()
   186 ms  free()
   186 ms  free()
   186 ms  free()
   187 ms  free()
   187 ms  free()
   187 ms  free()
   187 ms  free()
   187 ms  free()
   187 ms  free()
   188 ms  free()
{% endhighlight bash %}

Notice that, again, Frida has no inner understanding about `malloc`, `free` and their respective arguments. The `frida-trace` tool has generated handler stubs for us in the local directory, which we can modify to our liking.

Both stubs look something like this (discarding helpful comments):

{% highlight javascript %}
{
    onEnter: function (log, args, state) {
        log("free(" + "" + ")");
    },
    onLeave: function (log, retval, state) {
    }
}
{% endhighlight javascript %}

We can change these to supply us with useful information. In the case of `free`, we need only print the argument.

{% highlight javascript %}
{
    onEnter: function (log, args, state) {
        log("free(0x" + args[0].toString(16) + ")");
    }
}
{% endhighlight javascript %}

While for `malloc`, we're also interested in the return value.

{% highlight javascript %}
{
    onEnter: function (log, args, state) {
        log("malloc(" + args[0].toInt32() + ")");
    },
    onLeave: function (log, retval, state) {
		log("-> 0x" + retval.toString(16));
    }
}

{% endhighlight javascript %}

If we run `frida-trace` again, it will use the handlers we just modified.

{% highlight bash %}
$ frida-trace -i malloc -i free ./mallocs
Instrumenting functions...                                              
Started tracing 4 functions. Press Ctrl+C to stop.                      
           /* TID 0x5d2b */
   104 ms  malloc(80)
   104 ms  -> 0x80b840
   104 ms  malloc(32)
   104 ms  -> 0x80b8a0
   104 ms  malloc(32)
   104 ms  -> 0x80b8d0
   105 ms  malloc(32)
   105 ms  -> 0x80b900
   105 ms  malloc(32)
   105 ms  -> 0x80b930
   105 ms  malloc(32)
   105 ms  -> 0x80b960
   105 ms  malloc(32)
   105 ms  -> 0x80b990
   105 ms  malloc(32)
   105 ms  -> 0x80b9c0
   105 ms  malloc(32)
   105 ms  -> 0x80b9f0
   105 ms  malloc(32)
   105 ms  -> 0x80ba20
   105 ms  malloc(32)
   105 ms  -> 0x80ba50
   105 ms  malloc(4096)
   105 ms  -> 0x80ba80
   105 ms  free(0x80b8a0)
   105 ms  free(0x80b8d0)
   105 ms  free(0x80b900)
   105 ms  free(0x80b930)
   105 ms  free(0x80b960)
   105 ms  free(0x80b990)
   105 ms  free(0x80b9c0)
   105 ms  free(0x80b9f0)
   105 ms  free(0x80ba20)
   105 ms  free(0x80ba50)
   105 ms  free(0x80b840)
{% endhighlight bash %}

That's about it for this session. Stay tuned for more in the (hopefully) near future, when I'll dive into the Stalker API and provide a fun use-case.
