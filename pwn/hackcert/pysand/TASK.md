# PySand

Python 3.8 offers this awesome feature that makes Python sandboxes finally viable. Nobody will slip through.

nc ecsc19.hack.cert.pl 25011

Source code:

```python3
# sandbox.py

from os import path
player_code = input("Give me code:\n")
with open(path.join(path.dirname(__file__), "try_audit.py"), "r") as f:
    sandbox_code = f.read()
    sandbox_code += player_code
    exec(sandbox_code)

```



```python3
# try_audit.py

#!/usr/bin/env python3.8
import sys

class SecurityError(BaseException):
    pass

def audithook(name, tupla):
    raise SecurityError("Hackers not allowed. Tried to perform {}".format(name))

sys.addaudithook(audithook)
```