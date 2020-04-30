# Heroes of Might and PWN: 425pts, 4 solves
I love to play HoMM3 on different maps created by the community. However, yesterday my computer was hacked, right after loading a map received from a colleague. He is rather a 101 wannabe hacker, so I don't think that he invented the exploit himself. After small inspection, I've found out what the vulnerability is and got it patched. Let's see if you can still hack me.

http://heroes3pwn.ecsc19.hack.cert.pl
On the webpage, you may find HoMM3 Demo installer. The patched executable is named h3demo.exe, while the original one is named h3demo_unpatched.exe.
The server is running patched binary h3demo.exe (fde035e8d4dc6d94d6566b3f9fa0766900e8bfaf4761aff8a522fc65f7271c02).

## Important

The keyboard is not available over VNC session, you may only use mouse (we are too afraid of strange GUIs in Windows).
There is no network in the Virtual Machine, so don't try to create any kind of reverse shell.

Flag is in D:\flag.txt on the remote machine.
Flag format: ecsc19{letters_and_digits}.