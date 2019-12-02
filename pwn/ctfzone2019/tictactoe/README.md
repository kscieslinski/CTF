# Tictactoe (shellcode, proxy)

Notes:
- binary for proxy server given
- source code of python server given

## Enumeration
In this task we are given two files:

```bash
$ ls
tictactoe server.py

$ file tictactoe
tictactoe: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=292bbd6ea3adfb92195a360d1af03ce2757879ba, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Before digging into reverse engineering, let's get some basic idea about how the game works by playing it. From the task description we know it is some kind of tictactoe game. Let's connect to the provided host and port.

```bash
$ nc pwn-tictactoe.ctfz.one 8889
Welcome to tictactoe game! Please, enter your name: Ala
                                                                     
+---+---+---+    Session: ATuJ5lkz9qgmxinXMIun5JM2WOWHZn6f           
|   |   |   |                                                        
| X |   |   |     Player: Ala                                        
|  1|  2|  3|                                                        
|---+---+---|      Level: 1/100                                      
|   |   |   |                                                        
|   |   |   |      Rules: You play with 0s. Now it's your turn.      
|  4|  5|  6|             Enter number 1-9 to make your move.        
|---+---+---|             In order to get the flag you need to win   
|   |   |   |             100 times in a row, buy your enemy is a    
|   |   |   |             really smart AI. Good luck!                
|  7|  8|  9|                                                        
+---+---+---+      Enter your move (1-9): 5
                                                                     
+---+---+---+    Session: ATuJ5lkz9qgmxinXMIun5JM2WOWHZn6f           
|   |   |   |                                                        
| X | X |   |     Player: Ala                                        
|  1|  2|  3|                                                        
|---+---+---|      Level: 1/100                                      
|   |   |   |                                                        
|   | 0 |   |      Rules: You play with 0s. Now it's your turn.      
|  4|  5|  6|             Enter number 1-9 to make your move.        
|---+---+---|             In order to get the flag you need to win   
|   |   |   |             100 times in a row, buy your enemy is a    
|   |   |   |             really smart AI. Good luck!                
|  7|  8|  9|                                                        
+---+---+---+      Enter your move (1-9): 3
                                                                     
+---+---+---+    Session: ATuJ5lkz9qgmxinXMIun5JM2WOWHZn6f           
|   |   |   |                                                        
| X | X | 0 |     Player: Ala                                        
|  1|  2|  3|                                                        
|---+---+---|      Level: 1/100                                      
|   |   |   |                                                        
|   | 0 |   |      Rules: You play with 0s. Now it's your turn.      
|  4|  5|  6|             Enter number 1-9 to make your move.        
|---+---+---|             In order to get the flag you need to win   
|   |   |   |             100 times in a row, buy your enemy is a    
| X |   |   |             really smart AI. Good luck!                
|  7|  8|  9|                                                        
+---+---+---+      Enter your move (1-9): 4
                                                                     
+---+---+---+    Session: ATuJ5lkz9qgmxinXMIun5JM2WOWHZn6f           
|   |   |   |                                                        
| X | X | 0 |     Player: Ala                                        
|  1|  2|  3|                                                        
|---+---+---|      Level: 1/100                                      
|   |   |   |                                                        
| 0 | 0 | X |      Rules: You play with 0s. Now it's your turn.      
|  4|  5|  6|             Enter number 1-9 to make your move.        
|---+---+---|             In order to get the flag you need to win   
|   |   |   |             100 times in a row, buy your enemy is a    
| X |   |   |             really smart AI. Good luck!                
|  7|  8|  9|                                                        
+---+---+---+      Enter your move (1-9): 9
                                                                     
+---+---+---+    Session: ATuJ5lkz9qgmxinXMIun5JM2WOWHZn6f           
|   |   |   |                                                        
| X | X | 0 |     Player: Ala                                        
|  1|  2|  3|                                                        
|---+---+---|      Level: 1/100                                      
|   |   |   |                                                        
| 0 | 0 | X |      Rules: You play with 0s. Now it's your turn.      
|  4|  5|  6|             Enter number 1-9 to make your move.        
|---+---+---|             In order to get the flag you need to win   
|   |   |   |             100 times in a row, buy your enemy is a    
| X | X | 0 |             really smart AI. Good luck!                
|  7|  8|  9|                                                        
+---+---+---+      Enter your move (1-9): 


It's a lose (or draw may be), start over from first level
```

So the game asks a player to provide her/his name and then consecutively asks player for moves. The goal seems to be to own a computer 100 times. It seems impossible as computer starts the game, plays quite well and draws are marked as player loose. I've tried few times and havn't won even once.

Now let's understand the system architecture. As I've mentioned at the beginning we have two files: server.py and tictactoe. Which file did we connected to? I will spoiler a little bit and show you how the first flow looks like.

![](img/architecture0.png)
