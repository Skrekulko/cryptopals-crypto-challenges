### Offline dictionary attack on simplified SRP

S</br>
```
x = SHA256(salt|password)
    v = g**x % n
```

C->S</br>
```
I, A = g**a % n
```

S->C</br>
```
salt, B = g**b % n, u = 128 bit random number
```

C</br>
```
x = SHA256(salt|password)
    S = B**(a + ux) % n
    K = SHA256(S)
```

S</br>
```
S = (A * v ** u)**b % n
    K = SHA256(S)
```

C->S</br>
Send HMAC-SHA256(K, salt)

S->C</br>
Send "OK" if HMAC-SHA256(K, salt) validates</br>
Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.

Crack the password from A's HMAC-SHA256(K, salt).