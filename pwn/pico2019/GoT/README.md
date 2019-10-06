# GoT 350 points (pwn, pico, global-offset-table)

Notes:
- source code given
- binary given

### Enumeration
The program is very simple. It allows us to override exactly one address in the memory and to get the flag we have to call `win` function.

It also gives us a great hint. The GoT stands for global-offset-table.