## Crypto Challenge Set 6 - 41. Implement unpadded message recovery oracle

### Implement unpadded message recovery oracle

Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring". Here's why.

Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages which (again: Javascript) aren't padded before encryption at all.

You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit the same message twice: let's say the server keeps hashes of previous messages for some liveness interval, and that the message has an embedded timestamp:

```
{
  time: 1356304276,
  social: '555-55-5555',
}
```

You'd like to capture other people's messages and use the server to decrypt them. But when you try, the server takes the hash of the ciphertext and uses it to reject the request. Any bit you flip in the ciphertext irrevocably scrambles the decryption.

This turns out to be trivially breakable:

Capture the ciphertext C
- Let N and E be the public modulus and exponent respectively
- Let S be a random number > 1 mod N. Doesn't matter what.
- Now:
```
C' = ((S**E mod N) C) mod N
```
- Submit C', which appears totally different from C, to the server, recovering P', which appears totally different from P
- Now:
```
          P'
    P = -----  mod N
          S
```

Oops!

Implement that attack.

#### Careful about division in cyclic groups.

> Remember: you don't simply divide mod N; you multiply by the multiplicative inverse mod N. So you'll need a modinv() function.
> 
## Explanation

As we know, the RSA ciphertext $c$ and message $m$ have this form:

```math
\begin{matrix}
c\equiv m^e\bmod n
\\
m\equiv c^{d}\bmod n
\end{matrix}
```

Here's a quick proof that the message's form is correct:

```math
\begin{matrix}
m\equiv c^{d}\equiv (m^{e})^{d}\equiv m^{ed}\equiv m\bmod n
\\
(d\equiv e^{-1}\bmod n\Rightarrow ed\equiv 1 \bmod n)
\end{matrix}
```

We now construct our new ciphertext $c^{'}$ with a random number $s$ such that $s>1\bmod n$:

```math
c^{'}\equiv s^{e}c\bmod n
```

After submitting our new ciphertext $c^{'}$ to the server, we get the new plaintext $m^{'}$:

```math
m^{'}\equiv (c^{'})^{d}\equiv (s^{e}c)^{d}\equiv (s^{e}m^{e})^{d}\equiv sm\bmod n
```

You may now notice, that there's the original plaintext $m$ on the right side of the equation. To isolate it, we need to multiply both sides with the multiplicative inverse $s^{-1}$ of $s$:

```math
ms^{-1}\equiv sms^{-1}\equiv m\bmod n\Rightarrow \underline{ms^{-1}\equiv m\bmod n}
```

As you can see, we successfully recovered the original plaintext $m$.