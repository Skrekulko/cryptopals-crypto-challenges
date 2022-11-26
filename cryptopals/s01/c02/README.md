### Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

```
1c0111001f010100061a024b53535009181c
```

... after hex decoding, and when XOR'd against:

```
686974207468652062756c6c277320657965
```

... should produce:

```
746865206b696420646f6e277420706c6179
```

### Write-Up

First, because the two hex strings are provided as a normal string, they need to be converted into a byte string using the byte annotation:

```python
b"1c0111001f010100061a024b53535009181c"
b"686974207468652062756c6c277320657965"
```

or, the *fromhex*[^1] method from *bytes*[^2] object can be used:

```python
bytes.fromhex("1c0111001f010100061a024b53535009181c")
bytes.fromhex("686974207468652062756c6c277320657965")
```

Now that the hex strings are properly converted into a byte string, the XORing can take place.

The Python XOR[^3] operator "**\^**"[^4] can operate on *int* as well as on *bytes* object. The operator automatically converts the *bytes* object into an *int*, thus the byte strings can not be XORed against each other, since they would be converted into a huge number. Also the result of the operation is an *int*, so a conversion into a *bytes* needs to take place.

Each of the individual bytes of the strings need to be XORed against each other, and for that, *zip*[^5] can be used:

```python
a ^ b for (a, b) in zip(byte_string1, byte_string2)
```

Finally, the result needs to be converted back into a *bytes* object:

```python
bytes(a ^ b for (a, b) in zip(byte_string1, byte_string2))
```

[^1]: [fromhex](https://docs.python.org/3/library/stdtypes.html)

[^2]: [bytes](https://docs.python.org/3/library/stdtypes.html)

[^3]: [XOR](https://en.wikipedia.org/wiki/Exclusive_or)

[^4]: [Bitwise Exclusive Or](https://docs.python.org/3/library/operator.html)

[^5]: [zip](https://docs.python.org/3/library/functions.html#zip)
