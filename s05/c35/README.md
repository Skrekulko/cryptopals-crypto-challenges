### Implement DH with negotiated groups, and break with malicious "g" parameters

**A**->**B**</br>
Send "p", "g"</br>
**B**->**A**</br>
Send ACK</br>
**A**->**B**</br>
Send "A"</br>
**B**->**A**</br>
Send "B"</br>
**A**->**B**</br>
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv</br>
**B**->**A**</br>
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv</br>

Do the MITM attack again, but play with "g". What happens with:

```
    g = 1
    g = p
    g = p - 1
```

Write attacks for each.

#### When does this ever happen?

> Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.