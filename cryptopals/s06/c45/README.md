## DSA parameter tampering

Take your DSA code from the previous exercise. Imagine it as part of an algorithm in which the client was allowed to propose domain parameters (the p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into accepting bad parameters. Vaudenay gave two examples of bad generator parameters: generators that were 0 mod p, and generators that were 1 mod p.

Use the parameters from the previous exercise, but substitute 0 for "g". Generate a signature. You will notice something bad. Verify the signature. Now verify any other signature, for any other string.

Now, try (p+1) as "g". With this "g", you can generate a magic signature s, r for any DSA public key that will validate against any string. For arbitrary z:

```
  r = ((y**z) % p) % q

        r
  s =  --- % q
        z
```

Sign "Hello, world". And "Goodbye, world".

## Write-up

If we substitute $0$ for $g$, the signature and the verification process will look like this:

```math
\begin{align*}
\textrm{Public key:} &\\
y &\equiv g^{x}\equiv 0^{x}\equiv 0\bmod p\\
\textrm{Signature:} &\\
r &\equiv g^{k}\equiv 0^{k}\equiv 0\bmod p\\
s &\equiv k^{-1}(z+x\cdot r)\equiv k^{-1}(z+x\cdot 0)\equiv k^{-1}\cdot z\bmod p\\
\textrm{Verification:} &\\
w &\equiv (s^{'})^{-1}\equiv (k^{-1}\cdot z)^{-1}\bmod q\\
u_{1} &\equiv z\cdot w\equiv z\cdot (s^{'})^{-1}\equiv z\cdot (k^{-1}\cdot z)^{-1}\equiv k^{-1}\bmod q\\
u_{2} &\equiv r^{'}\cdot w\equiv 0\cdot w\equiv 0\bmod q\\
v &\equiv g^{u_{1}}\cdot y^{u_{2}}\equiv 0^{u_{1}}\cdot 0^{u_{2}}\equiv 0\bmod p\bmod q\\
v &\stackrel{?}{\equiv}r\rightarrow 0\stackrel{?}{\equiv}0
\end{align*}
```

As you can see, by substituting $0$ for $g$, the whole signing and verification process is broken. Now what happens if we substitu $p+1$ for $g$?

```math
\begin{align*}
\textrm{Public key:} &\\
y &\equiv g^{x}\equiv (p+1)^{x}\equiv 1\bmod p\\
\textrm{Signature:} &\\
r &\equiv g^{k}\equiv (p+1)^{k}\equiv 1\bmod p\\
s &\equiv k^{-1}(z+x\cdot r)\equiv k^{-1}(z+x\cdot 1)\equiv k^{-1}(z+x)\bmod p\\
\textrm{Verification:} &\\
w &\equiv (s^{'})^{-1}\equiv (k^{-1}\cdot z)^{-1}\bmod q\\
u_{1} &\equiv z\cdot w\equiv z\cdot (s^{'})^{-1}\equiv z\cdot (k^{-1}(z+x))^{-1}\bmod q\\
u_{2} &\equiv r^{'}\cdot w\equiv 1\cdot w\equiv w\equiv (s^{'})^{-1}\equiv (k^{-1}(z+x))^{-1}\bmod q\\
v &\equiv g^{u_{1}}\cdot y^{u_{2}}\equiv (p+1)^{u_{1}}\cdot 1^{u_{2}}\equiv 1\bmod p\bmod q\\
v &\stackrel{?}{\equiv}r\rightarrow 1\stackrel{?}{\equiv}1
\end{align*}
```

And once again, the system has been broken. Now in both circumstances you can verify any message with any signature.
