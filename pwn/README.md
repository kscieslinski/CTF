# PWN challenges
This is a collection of pwn challenges I've solved or partialy solved but wrote writeup in order to better understand the solution. I started learning about low level security on 10.2019. Most of the writeups are made only for myself so I can track my progress and store some useful tricks. Therefore they might be hard to understand and contain a lot of gramma mistakes.



## RITSEC CTF 2019
I participated in this CTF myself on a train ride. I've tried and completed two challenges: the easy bottles task and the jit-calc. The later one was really cool one and so I wrote writeup for it.
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/ritsec/jit-calc">jit-calc - 495 pts</a></td>
        <td>splitted shellcode</td>
        <td></td>
    </tr>
  </tbody>
</table>



## Pwnable.tw
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/seethefile">seethefile - 250 pts</a></td>
        <td>FSOP, vtable, fclose, glibc 2.23</td>
        <td>fclose + basic file structs explained</td>
    </tr>    
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/applestore">applestore - 200 pts</a></td>
        <td>stack pivoting, ebp overwrite</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/silver_bullet">Silver Bullet - 200 pts</a></td>
        <td>buffer overflow, off-by-one</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/hacknote">hacknote - 200 pts</a></td>
        <td>heap-exploitation, use-after-free, glibc 2.23-</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/dubblesort">dubblesort - 150 pts</a></td>
        <td>scanf + - vulnerability, buffer overflow, canary bypass</td>
        <td>patchelf + LD_PRELOAD</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/calc">calc - 150 pts</a></td>
        <td>stack machine, canary bypass</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/orw">owr - 100 pts</a></td>
        <td>shellcode, prctl</td>
        <td>explains prctl</td>
    </tr>
    
  </tbody>
</table>



## Exploit Education Phoenix
My friend has recommended this site to me. I do respect that it introduces core concepts about exploitation techniques. Moreover I love that it is prepared for many, not only amd architecture. Nevertheless I did not enjoyed it to much as the challenges lacked a plot :( The nice thing is that I've learned about format string vulnerability there. I've done all challenges except of heap exploitation ones as they seemed to be very similar to the easy ones at picoCTF 2019 (plus I think the final heap task had a mistake which made it very hard if not completely unexploitable)
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/phoenix/format-three">Format Three</a></td>
        <td>format-string, set address with qword value</td>
        <td></td>
    </tr>
  </tbody>
</table>



## PicoCTF 2019
This was my first CTF in which I've tried to solve a pwn challenge. I was super lucky to start learning about low level exploitation a week before this CTF started, so I had much fun competing in a complete new for me category. In the end I've solved all of the challenges except of: sice_cream, zero_to_hero and leap-frog. After the CTF I've fairly completed zero_to_hero task. I was very positively surprised that some of the challenges turned out to be quite demanding - especialy the heap exploitation ones.
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/zero_to_hero">zero_to_hero - 500 pts</a></td>
        <td>heap exploitation, glibc 2.29, off-by-one, tcache, __free_hook</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/Ghost_Diary">Ghost_Diary - 500 pts</a></td>
        <td>glibc 2.27, use-after-free, malloc_hook</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/HeapOverflow">HeapOverflow - 450 pts</a></td>
        <td>heap-exploitation, heap-overflow, unlink macro, free, GOT</td>
        <td>explains unlink macro</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/AfterLife">AfterLife - 400 pts</a></td>
        <td>heap-exploitation, use-after-free, unlink macro, GOT</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/GoT">GoT - 350 pts</a></td>
        <td>global-offset-table</td>
        <td>explains GoT</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/messy-malloc">messy-malloc - 300 pts</a></td>
        <td>heap, unclear-memory</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/CanaRy">CanaRy - 300 pts</a></td>
        <td>brute force canary byte by byte, buffer overflow</td>
        <td></td>
    </tr>
  </tbody>
</table>



## Security classes at University of Warsaw
This challenges come from in my opinion best entry level course for low level security in Polish. They introduce shellcodes, ret2libc, rop technique, pwntools framework and protection mechnisms as ASLR/DEP/CANARY. Moreover they are very entertaining both to read and to exploit. I totaly recomend the homework shellcode task in which one have to gain a control over SMTP server ([Archiwum xsmtp](https://www.mimuw.edu.pl/~kdr/bsk/lab7))
You can find the course [here](https://www.mimuw.edu.pl/~kdr/bsk/).
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/bsk/game">Game</a></td>
        <td>integer_overflow</td>
        <td></td>
    </tr>
    <tr>
        <td><a href="https://github.com/kscieslinski/CTF/tree/master/pwn/bsk/greeter2.0">Greeter2.0</a></td>
        <td>ret2libc, off-by-one, overwriting ra of function below</td>
        <td></td>
    </tr>
  </tbody>
</table>



<!-- Table schema:
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
    </tr>
    <tr>
        <td><a href=""></a></td>
        <td></td>
        <td></td>
    </tr>
  </tbody>
</table>
-->