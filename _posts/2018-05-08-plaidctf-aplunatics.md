---
layout: post
title: "PlaidCTF 2018 - APLunatic Writeup"
date: 2018-05-08 00:25:06
description: A reverse engineering challenge in APL
categories:
 - writeup
tags:
 - reversing
share: true
---

# Context

PlaidCTF was pretty neat and a bit wacky, as always. I managed to tackle a few challenges, one of them being this slice of insanity right here.

> Disclaimer: I am not an APL programmer, though I really enjoy the language from a conceptual point of view (terseness and expressivity through notation); and I have been called a lunatic on many occasions.

In this post, I will give you a brief overview of APL basics, since we will be using the language itself to solve the challenge. You may skip over it and go straight for the solution description if you're not interested (though you would be missing out on some ~~crazy~~ cool language features that APL provides).

At its core, APL is a functional programming language, dealing with functions and operators (higher-order functions which take other functions as arguments). One of the learning difficulties most often cited comes not from the high-level abstractions (I'm sure most of you are comfortable with Python's own `map`, `lambda`, `filter` and so on), but the notation used. APL has its own set of 50 (close to 80 in modern implementations) Unicode characters, each denoting a function or operator, making the code very dense (and the language very adequate for tasks such as code golfing) and somewhat challenging to read for newcomers.

# A quick introduction to APL

If you're up for some brain twisters, accompanied by the soothing voice of John Scholes, then I highly recommend [these](https://www.youtube.com/watch?v=DsZdfnlh_d0) [three](https://www.youtube.com/watch?v=DmT80OseAGs) [videos](https://www.youtube.com/watch?v=a9xAKttWgP4). If you need a more gentle introduction, then keep reading.

## Functions

A function in APL is denoted by a pair of curly braces (`{}`) containing an expression. Functions come in two flavors, monadic (or unary, single argument) and dyadic (binary, two arguments).

A monadic function has a single right-hand side argument, denoted by the formal parameter `⍵`. A dyadic function also has a left-hand side argument denoted by `⍺`.

{% highlight apl %}
⍝ The function f(x) = x + 1 applied to 1.
{⍵ + 1} 1
2

⍝ The function f(x,y) = x * y; note that "*" in APL is actually "pow"
2 {⍺ × ⍵} 5
10
{% endhighlight apl %}

## Arrays

APL works beautifully with arrays of any dimension. Most functions will work over arrays without any extra work from the programmer.

{% highlight apl %}
⍝ Numbers 1 through 8; APL is 1-indexed
⍳ 8
1 2 3 4 5 6 7 8

⍝ The "shape" of the previous array; for a 1D array, this will be the length
⍴ ⍳ 8
8

⍝ The 2x4 "reshape" of the array creates a 2D matrix
2 4 ⍴ ⍳ 8
1 2 3 4
5 6 7 8

⍝ Applying our simple function over the matrix
{⍵ + 1} 2 4 ⍴ ⍳ 8
2 3 4 5
6 7 8 9
{% endhighlight apl %}

You may have noticed that we used the same *rho* symbol to accomplish two related, but different things. Most symbols in APL denote both a monadic and a dyadic function. Depending on the presence of a left argument, functions will behave differently, which adds more difficulty in understanding APL code.

## Operators

These higher-order functions take other functions as arguments and applies them over data in various ways. This concept shouldn't be new to you, since Python's `map` does precisely that.

For instance, this is how we square all the numbers of a list in Python:

{% highlight python %}
map(lambda x: x*x, range(1,10))
[1, 4, 9, 16, 25, 36, 49, 64, 81]
{% endhighlight python %}

...and APL:

{% highlight apl %}
⍝ Reads as: "the squaring function applied to each of the numbers 1 through 9"
{⍵ × ⍵} ¨ ⍳ 9
1 4 9 16 25 36 49 64 81
{% endhighlight apl %}

APL has many more operators and functions, but in the name of brevity I won't cover them all. I'll introduce some new ones as needed while describing the challenge solution.

# The challenge

The code which we had to reverse was this:

{% highlight apl %}
⎕IO←0⋄'BIE°?½>IL½E.!!<E!:E84¥¸²E23Å8»968'{ {⍵(~⍵)/'success' 'fail'}⊃(+/⍺=⎕UCS 13+{+/⍵/⌽2*⍳⍴⍵}¨,/33 8⍴(8×⍴⍵)⍴7⌽⍉(-⌊(⍴'f0xtr0t')÷2)⌽⍉11 24⍴∊{a≠8↑(0,a←(8⍴2)⊤⍵)}¨⌽⎕UCS ⍵)=⍴⍺}'INPUT HERE'
{% endhighlight apl %}

Looks pretty daunting at first, but if we don't stray from basic principles, we can keep our sanity in check.

The `⎕IO←0⋄` seems superfluous. The diamond symbol is a statement separator; on its own, the statement reads a number from the standard input. We can safely move over this part.

From afar, the code can be simplified as follows: `'some result string' {some dyadic function} 'user input'`. That's all there is to it. My approach is to construct the inverse of this function such that, when applied on the result string, yields the original input. With that in mind, let's break the code down.

## String equality

How do we check to see if two strings are identical in APL? Let's construct such a function step by step:

{% highlight apl %}
⍝ The 'equals' function in APL behaves as expected on singular items
'a' = 'b'
0

'a' = 'a'
1

⍝ However, this behaviour changes in a slightly unexpected way when expanding it over arrays 
'abcd' = 'agcf'         
1 0 1 0

⍝ The simplest way to test string equality is to reduce (/) a logical AND over the resulting binary array
'abcd' {∧ / ⍺ = ⍵} 'agcf'
0

'abcd' {∧ / ⍺ = ⍵} 'abcd'    
1

⍝ We can then write a function which maps the values 1/0 over 'equal'/'not equal'
'abcd' { {⍵ (~⍵)/'equal' 'not equal'} ∧ / ⍺ = ⍵} 'abcd'
equal 
{% endhighlight apl %}

It's starting to look a bit like the 'success'/'fail' function in our challenge, but it's not quite there. The challenge maker chose a slightly more convoluted way of comparing strings. Instead of performing a logical AND over the resulting array, it sums the array and compares the sum with the length of the string, as in the following example:

{% highlight apl %}
'abcd' {+/⍺=⍵} 'agcf'
2

'abcd' {(+/⍺=⍵)=⍴⍺} 'abcd'
0

'abcd' {(+/⍺=⍵)=⍴⍺} 'abcd'
1
{% endhighlight apl %}

With the string comparison out of the way, we can further simplify our challenge by removing the 'success'/'fail' function and the equality test. Since the encoded flag was used only for comparison, we can store it away and convert the challenge into a monadic function.

## Conversions

We're down to the following code:

{% highlight apl %}
enc_flag ← 'BIE°?½>IL½E.!!<E!:E84¥¸²E23Å8»968'
challenge ← {⎕UCS 13+{+/⍵/⌽2*⍳⍴⍵}¨,/33 8⍴(8×⍴⍵)⍴7⌽⍉(-⌊(⍴'f0xtr0t')÷2)⌽⍉11 24⍴∊{a≠8↑(0,a←(8⍴2)⊤⍵)}¨⌽⎕UCS ⍵}
{% endhighlight apl %}

Again, staying with basic principles, analyzing APL functions can be done iteratively starting from the right. Our input string is denoted by the formal parameter `⍵`. `UCS` converts the string into an array of corresponding decimal ASCII values. `⌽` reverses the the array.

The next function in line is very interesting. Let's reconstruct it:

{% highlight apl %}
⍝ Eight twos
8⍴2
2 2 2 2 2 2 2 2

⍝ The "eight twos" (8bit) encoding of the value 123
(8⍴2)⊤123
0 1 1 1 1 0 1 1

⍝ We store the value in a and prepend a 0 to the result
{(0,a←(8⍴2)⊤⍵)} 123
0 0 1 1 1 1 0 1 1

⍝ We take the first 8 elements
{8↑(0,a←(8⍴2)⊤⍵)} 123
0 0 1 1 1 1 0 1

⍝ We compare if not equal...?
{a≠8↑(0,a←(8⍴2)⊤⍵)} 123
0 1 0 0 0 1 1 0

⍝ Actually, ≠ denotes XOR
1 0 1 ≠ 0 1 0            
1 1 1
{% endhighlight apl %}

What this code essentially does is `f(x) = x ^ (x >> 1)`; this XOR shift has some interesting properties, one being that successive elements differ in exactly one bit; we'll see another interesting property when we get to (finally) solving the challenge.

I'll skip the middle part in order to focus on another conversion function, namely `{+/⍵/⌽2*⍳⍴⍵}`. I'll leave it as an exercise to reconstruct it as before. This function can be read as: "The sum over omega over the reversed array of the powers of two", which is just a fancy way of saying binary-to-decimal. However, the ability to decode a binary number is implemented as primitive in APL:

{% highlight apl %}
{+/⍵/⌽2*⍳⍴⍵} 0 1 1 1 1 0 1 1
123

2⊥0 1 1 1 1 0 1 1
123
{% endhighlight apl %}

## Reshaping transposed rotations

The middle part which we haven't covered is this: `33 8⍴(8×⍴⍵)⍴7⌽⍉(-⌊(⍴'f0xtr0t')÷2)⌽⍉11 24⍴∊`

Again, in right-to-left order, the unary `∊` flattens our array of arrays of 8 bits into a single array of bits. Then we reshape these bits into an 11-by-24 matrix. This matrix then gets transposed, then rotated with a left argument given by `(-⌊(⍴'f0xtr0t')÷2)`. We can simply evaluate this part and see that we get the value `-3` (being the length of the string "f0xtr0t", divided by two, rounded down and sign-inverted).

This in turn goes through another transposition and another rotation, this time of `7`. This result first gets reshaped into a flat array of 264 bits (the result of `(8×⍴⍵)⍴`), which again gets reshaped into a 33 by 8 matrix. Lastly, each 8bit row of this matrix gets decoded back into decimal, giving us our resulting encoded flag.

## Reversal

To sum up what the encoding function did so far:

1. Convert the string from array of characters to array of corresponding ASCII decimals.
2. Reverse the array.
2. Convert each value to an array of 8 bits and apply `x^(x>>1)` over each.
3. Reshape into an 11-by-24 matrix.
4. Transpose and rotate by -3.
5. Transpose and rotate by 7.
6. Reshape into a 33-by-8 matrix.
7. Convert back to decimal. Add 13.
8. Convert back to "ASCII" (actually, APL uses Unicode by default).

All we need to do is go through the steps in reverse, making sure to change the order in which transpositions and rotations are performed.

{% highlight apl %}
⍝ Our encoded flag
enc_flag
BIE°?½>IL½E.!!<E!:E84¥¸²E23Å8»968

⍝ Convert to decimal
{⎕UCS ⍵} enc_flag                                          
66 73 69 176 63 189 62 73 76 189 69 46 33 33 60 69 33 58 69
      56 52 165 184 178 69 50 51 197 56 187 57 54 56

⍝ Subtract 13
{¯13+⎕UCS ⍵} enc_flag
53 60 56 163 50 176 49 60 63 176 56 33 20 20 47 56 20 45 56
      43 39 152 171 165 56 37 38 184 43 174 44 41 43

⍝ decimal to 8 bits function
bin ← {(8⍴2)⊤⍵}

⍝ Each element -> 8 bit array      
{bin¨ ¯13+⎕UCS ⍵} enc_flag

⍝ 11 by 24 reshape
{11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag

⍝ Reverse the transpositions and rotations
{⍉3⌽⍉¯7⌽11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag

⍝ The 33 by 8 reshape
{33 8⍴(8×⍴⍵)⍴⍉3⌽⍉¯7⌽11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag

⍝ Convert each 8 bit array to its corresponding value
{2⊥¨,/33 8⍴(8×⍴⍵)⍴⍉3⌽⍉¯7⌽11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag
67 96 112 94 40 40 90 112 40 78 112 86 75 49 87 76 112 74
      93 112 87 86 88 82 112 106 120 97 70 101 126 98 120
{% endhighlight apl %}

We're almost there, but we've hit a small bump in the road. How do we reverse the xorshift operation? Your first instinct could be to construct a lookup table for all 8 bit values (and that's how I did it during the CTF), but there's a more elegant solution.

## "Reversing" the xorshift

I don't know if there is a simple form for the inverse `xorshift^(-1)`, but I can experiment a bit with the function as is:

{% highlight apl %}
xsh ← {2⊥a≠8↑(0,a←(8⍴2)⊤⍵)}
xsh 50
43

xsh xsh 50
62

⍝ The function applied twice
(xsh ⍣ 2) 50 
62

(xsh ⍣ 3) 50
33

(xsh ⍣ 7) 50
35

(xsh ⍣ 8) 50  
50

⍝ Jackpot!
(xsh ⍣ 8) 123
123
{% endhighlight apl %}

As we can see, if we apply the function 8 times in a row, we get right back where we started. This means that if we apply it 7 times, it would be as if we applied the inverse of the function. We can also observe that for an N bit number, `xsh^(N-1) = xsh^(-1)`.

## End of the APLine

With this final piece, we have everything we need to construct our inverse challenge function:

{% highlight apl %}
⍝ Apply the "inverse" xorshift
{(xsh ⍣ 7)¨ 2⊥¨,/33 8⍴(8×⍴⍵)⍴⍉3⌽⍉¯7⌽11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag
125 64 95 107 48 48 108 95 48 116 95 100 114 33 101 119 95
      115 105 95 101 100 111 99 95 76 80 65 123 70 84 67 80

⍝ Convert back to ASCII
{⎕UCS(xsh ⍣ 7)¨ 2⊥¨,/33 8⍴(8×⍴⍵)⍴⍉3⌽⍉¯7⌽11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag
}@_k00l_0t_dr!ew_si_edoc_LPA{FTCP

⍝ Oops, forgot to reverse!
{⌽⎕UCS(xsh ⍣ 7)¨ 2⊥¨,/33 8⍴(8×⍴⍵)⍴⍉3⌽⍉¯7⌽11 24⍴∊bin¨ ¯13+⎕UCS ⍵} enc_flag
PCTF{APL_code_is_we!rd_t0_l00k_@}
{% endhighlight apl %}

So there you have it, a solution in APL which can fit in one tweet.

I hope you had fun reading (and perhaps even trying the code at [TryAPL](https://tryapl.org)). Protip: the backtick ``(`)`` can be used to enter APL's special characters (i.e. ``(`w)`` is `⍵`)

Big thanks to PPP for the CTF!
