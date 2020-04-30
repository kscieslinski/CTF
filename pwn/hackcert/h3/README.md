# Heroes of Might and PWN (windows, seh, game, VirtualAlloc)
This was a great challenge! It has also the lowest number of solves at [hackcert](https://hack.cert.pl/challenges) platform! It took me some time as I'm new to windows hacking and I spend a lot of time looking for setting the lab.

## CVE
From the story in task description we know that the server is running patched demo version of Heroes and Might and Magic 3. The unpatched version was vulnerable to some kind of popular exploit as it has been exploited by a script kiddie.

Searching through exploitdb I have quickly found the ['Heroes of Might and Magic III .h3m Map file Buffer Overflow'](https://www.exploit-db.com/exploits/37737) exploit from task description.

The exploit description states:
```
This module embeds an exploit into an ucompressed map file (.h3m) for
Heroes of Might and Magic III. Once the map is started in-game, a
buffer overflow occuring when loading object sprite names leads to
shellcode execution.
```

This raw description doesn't tell us to many details about where the vulnerability occurs. It just says that there is a buffer overflow in part of program responsible for parsing the sprite names.

## Patch
But we also received the patched version of the game. Problem was that the two executables: `h3demo.exe` and `h3demo_unpached.exe` are huge and I didn't want to reverse them manualy.
I needed a way to compare two raw `.exe` files. I love Ghidra and I find it way more intuitive then IDA, but I have to say that there is one big advantage of IDA over Ghidra – the number of avaible plugins.

As you have perhaps guessed, I've found <b>amazing</b> plugin for comparing `exe` filed. [diaphora](https://github.com/joxeankoret/diaphora) is not only well documented but really simple to use.

And so diaphora has found:

![](img/diaphora_diff.png)