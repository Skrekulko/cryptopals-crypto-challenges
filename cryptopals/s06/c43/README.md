## DSA key recovery from nonce

**Step 1**: Relocate so that you are out of easy travel distance of us.

**Step 2**: Implement DSA, up to signing and verifying, including parameter generation.

*Hah-hah you're too far away to come punch us.*

*Just kidding* you can skip the parameter generation part if you want; if you do, use these params:

```
 p = 800000000000000089e1855218a0e7dac38136ffafa72eda7
     859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
     2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
     ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
     b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
     1a584471bb1
 
 q = f4f47f05794b256174bba6e9b396a7707e563c5b
 
 g = 5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
     458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
     322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
     0f5b64c36b625a097f1651fe775323556fe00b3608c887892
     878480e99041be601a62166ca6894bdd41a7054ec89f756ba
     9fc95302291
```

("But I want smaller params!" Then generate them yourself.)

The DSA signing operation generates a random subkey "k". You know this because you implemented the DSA sign operation.

This is the first and easier of two challenges regarding the DSA "k" subkey.

Given a known "k", it's trivial to recover the DSA private key "x":

```
          (s * k) - H(msg)
      x = ----------------  mod q
                  r
```

Do this a couple times to prove to yourself that you grok it. Capture it in a function of some sort.

Now then. I used the parameters above. I generated a keypair. My pubkey is:

```
  y = 84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
      abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
      e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
      1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
      bb283e6633451e535c45513b2d33c99ea17
```

I signed

```
For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
```

(My SHA1 for this string was *d2d0714f014a9784047eaeccf956520045c45265*; I don't know what NIST wants you to do, but when I convert that hash to an integer I get: *0xd2d0714f014a9784047eaeccf956520045c45265*).

I get:

```
  r = 548099063082341131477253921760299949438196259240
  s = 857042759984254168557880549501802188789837994940
```

I signed this string with a broken implemention of DSA that generated "k" values between 0 and 2^16. What's my private key?


Its SHA-1 fingerprint (after being converted to hex) is:

```
0954edd5e0afe5542a4adf012611a91912a3ec16
```

Obviously, it also generates the same signature for that string.

## Write-up

NIST describes DSA (DSS) in [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final). Long story short, DSA consists of two basic parts (functions): *sign* and *verify (and validation)*.

DSA Signature Generation:

```math
\begin{aligned}
1.\;&\begin{aligned}
\textrm{A new secret random number $k$, sucht that $k\in \left \langle 1,q-1 \right \rangle$, $\textbf{shall}$ be generated prior to the generation of each digital signature for use during}
\end{aligned}\\
&\begin{aligned}
\textrm{the signature generation process. This secret number $\textbf{shall}$ be protected from unauthorized disclosure and modification.}
\end{aligned}\\
2.\;&\begin{aligned}
\textrm{Let $N$ be the bit length of $q$. Let $\textbf{min}(N, outlen)$ denote the minimum of the positive integers $N$ and $outlen$, where $outlen$ is the bit length}\
\end{aligned}\\
&\begin{aligned}
\textrm{of the hash function output block.}
\end{aligned}\\
3.\;&\begin{aligned}
\textrm{The signature of a message $M$ consists of the pair of numbers $r$ and $s$ that is computed according to the following equations:}
\end{aligned}\\
&\begin{aligned}
r=(g^{k}\bmod p)\bmod q
\end{aligned}\\
&\begin{aligned}
\textrm{$z=$ the left most $\textbf{min}(N,outlen)$ bits of $\textbf{Hash}(M^{'})$.}
\end{aligned}\\
&\begin{aligned}
s=k^{-1}(z+x\cdot r)\bmod q
\end{aligned}\\
4.\;&\begin{aligned}
\textrm{The signature (r, s) may be transmitted along with the message to the verifier.}
\end{aligned}
\end{aligned}
```

DSA Signature Verification and Validation:

```math
\begin{aligned}
1.\;&\begin{aligned}
\textrm{The verifier $\textbf{shall}$ check that $ 0 < r^{'} < q $ and $0 < s^{'} < q $; if either condition is violated, the signature $\textbf{shall}$ be rejected as invalid.}
\end{aligned}\\
2.\;&\begin{aligned}
\textrm{If the two conditions in step 1 are satisfied, the verifier computes the following:}
r=(g^{k}\bmod p)\bmod q
\end{aligned}\\
&\begin{aligned}
w=(s^{'})^{-1}\bmod q
\end{aligned}\\
&\begin{aligned}
\textrm{$z=$ the left most $\textbf{min}(N,outlen)$ bits of $\textbf{Hash}(M^{'})$.}
\end{aligned}\\
&\begin{aligned}
u_{1}=z\cdot w\bmod q
\end{aligned}\\
&\begin{aligned}
u_{2}=r^{'}\cdot w\bmod q
\end{aligned}\\
&\begin{aligned}
v=(g^{u_{1}}\cdot y^{u_{2}}\bmod p)\bmod q
\end{aligned}\\
3.\;&\begin{aligned}
\textrm{If $v=r^{'}$, then the signature is verified.}
\end{aligned}\\
4.\;&\begin{aligned}
\textrm{If $v$ does not equal $r^{'}$, then the message or the signature may have been modified, there may have been an error in the signatory’s generation process,}
\end{aligned}\\
&\begin{aligned}
\textrm{or an imposter (who did not know the private key associated with the public key of the claimed signatory) may have attempted to forge the signature.}
\end{aligned}\\
&\begin{aligned}
\textrm{The signature $\textbf{shall}$ be considered invalid. No inference can be made as to whether the data is valid, only that when using the public key to verify}
\end{aligned}\\
&\begin{aligned}
\textrm{the signature, the signature is incorrect for that data.}
\end{aligned}
\end{aligned}
```

According to the challenge, the private key $x$ should be computed by brute-forcing the small key $k$ used for signing. Since $r$ and $s$ are leaked, we can reconstruct the equation for so that we have the private key $x$ on the left side:

```math
s\equiv k^{-1}(z+x\cdot r)\bmod q\Rightarrow x\equiv (s\cdot k-z)\cdot r^{-1}\bmod q
```

Since we only know $r$, $s$, $z$ and $q$, with only $k$ being unknown (not counting $x$, since that's what we want to find out), we have to brute-force $k$, until we get a valid $x$, which we use to sign the message $M$ and then compare the $r^{'}$, $s^{'}$ with $r$, $s$. If they're equal, we found the correct private key $x$.
