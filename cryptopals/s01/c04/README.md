### Detect single-character XOR

One of the 60-character strings in file 4.txt has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

### Write-Up

This one's pretty simple. First the ciphertext needs to be parsed into lines. For this, the *with*[^1] statement and *open*[^2] function is used: 

```python
with open(file_name) as file:
    return [bytes.fromhex(line.rstrip()) for line in file.readlines()]
```

After the parsing is done, the solution from previous challenge is used, where the plaintext with minimal letter frequency is choosen, by using the *min*[^3] function and the *lambda*[^4] expression:

```python
plaintext = [single_byte_xor(ciphertext) for ciphertext in ciphertexts]

return min(plaintext, key=lambda t: t[2])
```

After getting the plaintext with the best letter frequency distribution, the correct answer should be:

```
Now that the party is jumping
```

[^1]: [with](https://docs.python.org/3/reference/compound_stmts.html#the-with-statement)

[^2]: [open](https://docs.python.org/3/library/functions.html#open)

[^3]: [min](https://docs.python.org/3/library/functions.html#min)

[^4]: [lambda](https://docs.python.org/3/reference/expressions.html#lambdas)
