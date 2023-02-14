## DSA nonce recovery from repeated nonce

#### Cryptanalytic MVP award.

> This attack (in an elliptic curve group) broke the PS3. It is a great, great attack.

In the file **44.txt** find a collection of DSA-signed messages. (NB: each msg has a trailing space.)

These were signed under the following pubkey:

```
y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
    2971c3de5084cce04a2e147821
```

(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have accidentally used a repeated "k". Given a pair of such messages, you can discover the "k" we used with the following formula:

```
         (m1 - m2)
     k = --------- mod q
         (s1 - s2)
```

#### 9th Grade Math: Study It!

> If you want to demystify this, work out that equation from the original DSA equations.

#### Basic cyclic group math operations want to screw you

> Remember all this math is mod q; s2 may be larger than s1, for instance, which isn't a problem if you're doing the subtraction mod q.
If you're like me, you'll definitely lose an hour to forgetting a paren or a mod q. (And don't forget that modular inverse function!)

What's my private key? Its SHA-1 (from hex) is:

```
ca8f6f7c66fa362d40760d135b763eb8527d3d52
```

## Write-up

When signing a message, the second component (signature) has the following term:

```math
s\equiv k^{-1}(z+x\cdot r)\bmod q
```

The private key $x$ is then expressed as:

```math
x\equiv (s\cdot k-z)r^{-1}\bmod q
```

Since we know the intermediate values $r$ and $s$, the only unknown value is the random integer $k$. But Due to the bad implementation of the DSA cryptosystem,
the random value $k$ is used every single time, meaning it stays the same. This allows us to form a system of equations:

```math
\begin{align*}
x &\equiv (s_{1}\cdot k-z_{1})r_{1}^{-1}\bmod q\\ 
x &\equiv (s_{2}\cdot k-z_{2})r_{2}^{-1}\bmod q
\end{align*}
```

We'll rearrange the first equation to express the random value $k$:

```math
\begin{align*}
x &\equiv (s_{1}\cdot k-z_{1})r_{1}^{-1}\bmod q\\ 
x\cdot r_{1} &\equiv (s_{1}\cdot k-z_{1})\cancel{r_{1}\cdot r_{1}^{-1}}\bmod q\\
x\cdot r_{1}+z_{1} &\equiv s_{1}\cdot k\cancel{-z_{1}+z_{1}}\bmod q\\
(x\cdot r_{1}+z_{1})\cdot s_{1}^{-1} &\equiv \cancel{s_{1}\cdot s_{1}^{-1}}\cdot k\bmod q\\
k &\equiv (x\cdot r_{1}+z_{1})s_{1}^{-1}\bmod q
\end{align*}
```

Now we use the second equation as a substitution in the first one:

```math
k\equiv \left [ (s_{2}\cdot k-z_{2})r_{2}^{-1}\cdot r_{1}+z_{1} \right ]s_{1}^{-1}\bmod q
```

Good, now tje "hard" part; express $k$ so that it is only on one side of the equation:

```math
\begin{align*}
k &\equiv \left [ (s_{2}\cdot k-z_{2})r_{2}^{-1}\cdot r_{1}+z_{1} \right ]s_{1}^{-1}\bmod q\\
k &\equiv (s_{2}\cdot k-z_{2})r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}+z_{1}\cdot s_{1}^{-1}\bmod q\\
k &\equiv s_{2}\cdot k\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}-z_{2}\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}+z_{1}\cdot s_{1}^{-1}\bmod q\\
k-s_{2}\cdot k\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1} &\equiv \cancel{s_{2}\cdot k\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}-s_{2}\cdot k\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}}+s_{1}^{-1}(z_{1}-z_{2}\cdot r_{2}^{-1}\cdot r_{1})\bmod q\\
k(1-s_{2}\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}) &\equiv s_{1}^{-1}(z_{1}-z_{2}\cdot r_{2}^{-1}\cdot r_{1})\bmod q\\
k &\equiv \frac{s_{1}^{-1}(z_{1}-z_{2}\cdot r_{2}^{-1}\cdot r_{1})}{1-s_{2}\cdot r_{2}^{-1}\cdot r_{1}\cdot s_{1}^{-1}}\bmod q
\end{align*}
```

Finally! Now we could calculate the random value $k$, but there is one more problem to solve. We can't just divide in a multiplicative group. Division is done
by multiplicative group by multiplying with a modular inverse. That means, we have to find a multiplicative inverse for the denominator. Let the nominator be $a$,
and the denominator $b$.

```math
k\equiv \frac{a}{b}\equiv a\cdot b^{-1}\bmod q
```

After correctly expressing $k$, it can be used to solve the private key $x$:

```math
x\equiv (s\cdot k-z)r^{-1}\bmod q
```

Successfully broken!





