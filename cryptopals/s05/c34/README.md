### Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:

**A**->**B**</br>
Send "p", "g", "A"</br>
**B**->**A**</br>
Send "B"</br>
**A**->**B**</br>
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv</br>
**B**->**A**</br>
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv</br>

(In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with random IVs appended or prepended to the message).

Now implement the following MITM attack:

**A**->**M**</br>
Send "p", "g", "A"</br>
**M**->**B**</br>
Send "p", "g", "p"</br>
**B**->**M**</br>
Send "B"</br>
**M**->**A**</br>
Send "p"</br>
**A**->**M**</br>
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv</br>
**M**->**B**</br>
Relay that to B</br>
**B**->**M**</br>
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv</br>
**M**->**A**</br>
Relay that to A

M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the parameter injection attack; it's going to come up again.