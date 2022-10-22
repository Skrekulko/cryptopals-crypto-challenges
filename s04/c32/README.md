### Break HMAC-SHA1 with a slightly less artificial timing leak

Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)

Now break it again.

### Notes

This challenge is identical to the last one because it can be solved using the same statistical approach.

And one again, since the pytest timeout is exceeded here by ***a lot***, it can be disabled for this challenge by the following:

"""
[tool.pytest.ini_options]
timeout = -1
"""
