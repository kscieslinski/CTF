# PWN challenges
This is a collection of pwn challenges I've solved (or partialy solved but wrote writeup to learn)



## Pwnable.tw
<table>
  <tbody>
    <tr>
        <th align="center">Challenge</th>
        <th align="center">Tags</th>
        <th align="center">Notes</th>
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