## Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

#### Degree of difficulty: moderate

> These next two challenges are the hardest in the entire set.

Let us Google this for you: ["Chosen ciphertext attacks against protocols based on the RSA encryption standard"](http://lmgtfy.com/?q=%22Chosen+ciphertext+attacks+against+protocols+based+on+the+RSA+encryption+standard%22)

This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions on the first search page.

Read the paper. It describes a padding oracle attack on PKCS#1v1.5. The attack is similar in spirit to the CBC padding oracle you built earlier; it's an "adaptive chosen ciphertext attack", which means you start with a valid ciphertext and repeatedly corrupt it, bouncing the adulterated ciphertexts off the target to learn things about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It involves 9th grade math, but also has you implementing an algorithm that is complex on par with finding a minimum cost spanning tree.

The setup:

- Build an oracle function, just like you did in the last exercise, but have it check for plaintext[0] == 0 and plaintext[1] == 2.

- Generate a 256 bit keypair (that is, p and q will each be 128 bit primes), [n, e, d].

- Plug d and n into your oracle function.

- PKCS1.5-pad a short message, like "kick it, CC", and call it "m". Encrypt to to get "c".

- Decrypt "c" using your padding oracle.

For this challenge, we've used an untenably small RSA modulus (you could factor this keypair instantly). That's because this exercise targets a specific step in the Bleichenbacher paper --- Step 2c, which implements a fast, nearly O(log n) search for the plaintext.

Things you want to keep in mind as you read the paper:

- RSA ciphertexts are just numbers. 

- RSA is "homomorphic" with respect to multiplication, which means you can multiply c * RSA(2) to get a c' that will decrypt to plaintext * 2. This is mindbending but easy to see if you play with it in code --- try multiplying ciphertexts with the RSA encryptions of numbers so you know you grok it.

- What you need to grok for this challenge is that Bleichenbacher uses multiplication on ciphertexts the way the CBC oracle uses XORs of random blocks. 

- A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a number between 02:00:00...00 and 02:FF:FF..FF --- in other words, 2B and 3B-1, where B is the bit size of the modulus minus the first 16 bits. When you see 2B and 3B, that's the idea the paper is playing with.

To decrypt "c", you'll need Step 2a from the paper (the search for the first "s" that, when encrypted and multiplied with the ciphertext, produces a conformant plaintext), Step 2c, the fast O(log n) search, and Step 3.

Your Step 3 code is probably not going to need to handle multiple ranges.

We recommend you just use the raw math from paper (check, check, double check your translation to code) and not spend too much time trying to grok how the math works.

## Write-up

This attack is based on the [paper](https://link.springer.com/chapter/10.1007/BFb0055716) published by Bleichenbacher. It is a chosen ciphertext attack against protocols based on the RSA encryption standard PKCS #1, more specifically the RSAES-PKCS1-v1_5 encryption, which is specified in the [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html).

We're going to cite the math behind the attack, without really explaining on how to implement it... Just take a look on the code. (Implementing this gave a pretty good headache.) Okay, let's start.

**Step 1: Blinding.** Given an integer $c$, choose different random integers $s_{0}$; then check, by accessing the oracle, whether $c(s_{0})^{e}\bmod n$ is PKCS conforming. For the first successful value $s_{0}$, set

```math
\begin{aligned}
c_{0}&\leftarrow c(s_{0})^{e}\bmod n
\\
M_{0}&\leftarrow \{[2B,3B-1]\}
\\
i&\leftarrow 1
\end{aligned}
```

Please take a note, that this step can bi skipped if $c$ is already PKCS conforming (i.e., when $c$ is an encrypted message). In that case, we set $s_{0}\leftarrow 1$. However, step 1 is always necessary for computing a signature, even if we do not wish to get a blind signature.

**Step 2: Searching for PKCS conforming messages.**

**Step 2.a: Starting the search.** If $i=1$, then search for the smallest positive integer $s_{1}\geq n/(3B)$, such that the ciphertext $c_{0}(s_{1})^{e}\bmod n$ is PKCS conforming.

**Step 2.b: Searching with more than one interval left.** Otherwise, if $i>1$ and the number of intervals in $M_{i-1}$ is at least $2$, then search for the smallest integer $s_{i}>s_{i-1}$, such that the ciphertext $c_{0}(s_{i})^{e}\bmod n$ is PKCS conforming.

**Step 2.c: Searching with one interval left.** Otherwise, if $M_{i-1}$ contains exactly one interval (i.e., $M_{i-1}=\\{[a,b]\\}$), then choose small integer values $r_{i}$, $s_{i}$ such that

```math
r_{i}\geq 2\frac{bs_{i-1}-2B}{n}
```

and

```math
\frac{2B+r_{i}n}{b}\leq s_{i}<\frac{3B+r_{i}n}{a}
```

until the ciphertext $c_{0}(s_{i})^{e}\bmod n$ is PKCS conforming.

**Step 3: Narrowing the set of solutions.** After $s_{i}$ has beed found, the set $M_{i}$ is computed as

```math
\begin{matrix}
M_{i}\leftarrow\bigcup\limits_{(a,b,r)}\left \{ \left [ \max\left ( a,\left \lceil \frac{2B+rn}{s_{i}} \right \rceil \right ),\min\left ( b,\left \lfloor \frac{3B-1+rn}{s_{i}} \right \rfloor \right ) \right ] \right \}
\\
\textrm{for all }[a,b]\in M_{i-1}\textrm{ and }\frac{as_{i}-3B+1}{n}\leq r\leq\frac{bs_{i}-2B}{n}.
\end{matrix}
```

**Step 4: Computing the solution.** If $M_{i}$ contains only one interval of length $1$ (i.e., $M_{i}={[a,a]}$), then set $m\leftarrow a(s_{0})^{-1}\bmod n$, and return $m$ as solution of $m\equiv c^{d}\bmod n$. Otherwise, set $i\leftarrow i+1$ and go to step 2.

And this is basically it. For quick results run it on a 256-bit RSA, otherwise you will need to wait *a bit*.
