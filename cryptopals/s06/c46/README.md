## RSA parity oracle

#### When does this ever happen?

> This is a bit of a toy problem, but it's very helpful for understanding what RSA is doing (and also for why pure number-theoretic encryption is terrifying). Trust us, you want to do this before trying the next challenge. Also, it's fun.

Generate a 1024 bit RSA key pair.

Write an oracle function that uses the private key to answer the question "is the plaintext of this message even or odd" (is the last bit of the message 0 or 1). Imagine for instance a server that accepted RSA-encrypted messages and checked the parity of their decryption to validate them, and spat out an error if they were of the wrong parity.

Anyways: function returning true or false based on whether the decrypted plaintext was even or odd, and nothing else.

Take the following string and un-Base64 it in your code (without looking at it!) and encrypt it to the public key, creating a ciphertext:

```
VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==
```

With your oracle function, you can trivially decrypt the message.

Here's why:

- RSA ciphertexts are just numbers. You can do trivial math on them. You can for instance multiply a ciphertext by the RSA-encryption of another number; the corresponding plaintext will be the product of those two numbers.

- If you double a ciphertext (multiply it by (2**e)%n), the resulting plaintext will (obviously) be either even or odd.

- If the plaintext after doubling is even, doubling the plaintext *didn't wrap the modulus* --- the modulus is a prime number. That means the plaintext is less than half the modulus.

You can repeatedly apply this heuristic, once per bit of the message, checking your oracle function each time.

Your decryption function starts with bounds for the plaintext of [0,n].

Each iteration of the decryption cuts the bounds in half; either the upper bound is reduced by half, or the lower bound is.

After log2(n) iterations, you have the decryption of the message.

Print the upper bound of the message as a string at each iteration; you'll see the message decrypt "hollywood style".

Decrypt the string (after encrypting it to a hidden private key) above.

## Write-up

This is a pretty good example of a side-channel attack. The oracle is giving us a partial information about the plaintext message. This partial information is the *parity* of the plaintext message, which might seem to be innocuous, but it can be fully exploited to recover the whole ciphertext message.

It is known, that the plaintext message $m$ can end up with a $1$ or $0$ bit. Now, think about multiplying $m$ by 2, modulo $n$. If

```math
m\in \left \langle 0,\frac{n}{2} \right \rangle \cup \left \{ n \right \}\Rightarrow 2\cdot m \equiv 2\cdot m\bmod n
```

then, which is even. If instead

```math
m\in \left ( \frac{n}{2}, n-1 \right )\Rightarrow 2\cdot m\equiv 2\cdot m-n\bmod n
```

which is odd given that $n$ is always odd, since its a product of two very large primes. Thus, if we multiply the ciphertext $c$ by the encryption of $2$, and we call the parity oracle on the obtained ciphertext, we discover whether the plaintext message is in the even or the odd interval. Quick proof that we can multiply the ciphertext by the encryption of $2$:

```math
(2^{e}\cdot c)^{d}\equiv (2^{e}\cdot m^{e})^{d}\equiv 2^{e\cdot d}\cdot m^{e\cdot d}\equiv 2\cdot m\bmod n
```

This argument is easily generalized to $2^{i}\cdot m\bmod n$ for the i-th step. This is sufficient to execute a *binary search*: at each step, we divide the interval of potential plaintexts in two and then descend into the correct one based on the parity revealed by the oracle. For arbitrary precision floats, we can utilize *Decimal* in Python, which makes it simple to divide intervals in half without approximation mistakes. The total amount off iterations needed is:

```math
\left \lceil \log_{2}{n} \right \rceil - 1
```
