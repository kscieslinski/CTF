# Collection (sandbox, cpython, type confusion)
This challenge was marked as easy and so I thought it might be a good task for first python sandbox escape task. I was wrong and in the end I had to glance few times to some other writeups which I found on web.
But besides that I have to say that this challenge has opened my eyes as I would never thought that high level languages such as python can be treated as reallistic target. I would like to recommend [this](https://hackernoon.com/python-sandbox-escape-via-a-memory-corruption-bug-19dde4d5fea5) writeup from bug bounty program which I found online when searching for some cpython exploitation examples.

## Intro
We are given a bunch of files:

```console
$ ls
libc-2.27.so test.py Collection.cpython-36m-x86_64-linux-gnu.so python3.6 server.py
```

The main file is `server.py`. It reads user provided code and then executes it. The goal is to read a flag file content. Moreover we are given a file descriptor to the open flag file, so all we need to do is to read from this flag descriptor and write the loaded content to stdout:

```python3
# server.py
flag = open("flag", "r")

prefix = """
from sys import modules
del modules['os']
import Collection
keys = list(__builtins__.__dict__.keys())
for k in keys:
    if k != 'id' and k != 'hex' and k != 'print' and k != 'range':
        del __builtins__.__dict__[k]

"""

code = prefix
new = ""
finished = False

while size_max > len(code):
    new = input("code> ")
    if new == "END_OF_PWN":
        finished = True
        break
    code += new + "\n"

if not finished:
    print("max length exceeded")
    sys.exit(42)


file_name = "/tmp/%s" % randstr()
with open(file_name, "wb+") as f:
    f.write(code.encode())


os.dup2(flag.fileno(), 1023)
flag.close()

cmd = "python3.6 -u %s" % file_name
os.system(cmd)


```

There is one flaw. Before our code gets interpreted, the prefix code gets interpreted:

```python3
from sys import modules
del modules['os']
import Collection
keys = list(__builtins__.__dict__.keys())
for k in keys:
    if k != 'id' and k != 'hex' and k != 'print' and k != 'range':
        del __builtins__.__dict__[k]
```

It imports custom Collection module, deletes 'os' and all builtins methods except of `id`, `hex`, `print` and `range`.

So in fact this code is setting a python sandbox.

## Collection.so
As I've mentioned at the beginning it was my first python escape challenge and so I wasn't sure where to look for vulnerabilities. I thought that it has to do with the way `modules` has been imported and I've wasted some time trying to escape this sandbox without touching Collection.so library.

But as I saw no progres, I've moved onto reverse engineering the Collection.so file.
Looking at `test.py` and using `dir` method I knew that Collection has some `__init__`, `__new__` and `get` methods.
```console
$ python3
import Collection
dir(Collection.Collection)
['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'get']
```

## Seccomp
So how to start reversing cpython module? Well refering to the [documentation](https://docs.python.org/3/extending/extending.html) every module has PyInit_modulename function. This function is being invoked when module is imported. And so it was my starting point:

```c
PyObject* PyInit_Collection() {
    PyObject *module;

    PyType_Ready(&type);
    module = PyModule_Create2(&def,0x3f5);
    if (module != 0) {
        _type = _type + 1;
        PyModule_AddObject(module,0x102740,&type);
        mprotect((void *)0x439000,1,7);
        [...]
        mprotect((void *)0x439000,1,5);
        init_sandbox();
    }
    return module;
}
```

so the only interesting part was `init_sandbox` function. It was only setting some seccomp rules. I hate to reverse those rules by hand, so I've used `seccomp-tools` to dump them.

```console
$ seccomp-tools
$ seccomp-tools dump -c "python3 test.py"
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0012
 0011: 0x05 0x00 0x00 0x00000011  goto 0029
 0012: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000019  if (A != mremap) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000013  if (A != readv) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x000000ca  if (A != futex) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000083  if (A != sigaltstack) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0026
 0025: 0x05 0x00 0x00 0x00000037  goto 0081
 0026: 0x15 0x00 0x01 0x0000000d  if (A != rt_sigaction) goto 0028
 0027: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0028: 0x06 0x00 0x00 0x00000000  return KILL
```

Not useful right now, but might be helpful later on. For now I've patched the `init_sandbox` with nops as those rules where really anoying. For example with unpatched `init_sandbox` I was unable to import module after `import Collection` instruction.

## __new__
