### Convert hex to base64

The string:

```
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
```

Should produce:
```
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

#### Cryptopals Rule
> Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.


### Write-Up

The *encode*[^1] and *decode*[^2] functions from the *codecs*[^3] package is used to encode/decode, and *rstrip*[^4] is used to get rid of any end characters.

First, the hex string

```
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
```

is decoded into an ASCII string,

```
I'm killing your brain like a poisonous mushroom
```

which is then finally encoded into a Base64 string.

```
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

[^1]: [codecs](https://docs.python.org/3/library/codecs.html#codecs.encode)

[^2]: [codecs](https://docs.python.org/3/library/codecs.html#codecs.decode)

[^3]: [codecs](https://docs.python.org/3/library/codecs.html)

[^4]: [rstrip](https://docs.python.org/3/library/stdtypes.html#str.rstrip)
