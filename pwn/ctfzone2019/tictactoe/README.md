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

Now let's understand the system architecture. As I've mentioned at the beginning we have two files: server.py and tictactoe. Which file did we connected to? I will spoiler a little bit and show you how the flow of first request looked like.

![](img/architecture0.png)

The tictactoe is a proxy server. Client cannot directly connect to server.py as he doesn't know the ip address of it and it is protected by firewall (or at least should, I havn't tried this attack vector).

Ok, so what's the goal? Should we pwn the tictactoe proxy server or server.py? It is obvious when we start reading the source code of server.py:

```python
if __name__ == '__main__':
    try:
        FLAG = os.environ.get('FLAG')
    except Exception as e:
        print('[-] Can\'t get flag: {}'.format(e))
        exit(0)
    start_server(HOST, PORT)
```

The flag is located in server.py ram. And as the game says the player has to win 100 games in order to get the flag:

```python
class TicTacToeServerHandler(socketserver.BaseRequestHandler):
    sessions = {}

    def handle(self):
        try:
            data = str(self.request.recv(1), 'ascii')
            if data[0] == REG_USER:
                self.process_reg_user()
            elif data[0] == SEND_STATE:
                self.process_state()
            elif data[0] == GET_FLAG:   
                self.process_flag()
        except Exception as e:
            print('[-] Error handling messages: {}'.format(e))

    def process_reg_user(self):
        [...]

    def process_flag(self):
        unpacker = struct.Struct('<32s')
        input_bytes = self.request.recv(32)
        session = unpacker.unpack(input_bytes)
        session = str(session[0], 'ascii')
        if session not in self.sessions:
            err = ERROR_SESS
            msg = "You trying to cheat on me!\n"
        elif self.sessions[session]['level'] < FLAG_COUNT: # check if user won 100 games
            err = ERROR_SESS
            msg = "You trying to cheat on me!\n"
        else:
            err = ERROR_NO
            msg = FLAG

        try:
            packer = struct.Struct('<i {}s'.format(len(msg)))
            values = (err, bytes(msg, 'ascii'))
            packed_data = packer.pack(*values)
            self.request.sendall(packed_data)
            print('[+] Sending flag info: {} {}'.format(binascii.hexlify(packed_data), values))
        except Exception as e:
            print('[-] Error sending flag response: {}'.format(e))

    def process_state(self):
        [...]

    def get_state_response(self, session, cmove, hmove):
        [...]

    def check_win(self, field):
        [...]

    def generate_session(self):
        [...]
```

So to get the flag a proxy server has to send GET_FLAG request to server.py. Then server.py will double check if the user really has won the game 100 times. One would ask why the server.py has to check the message from tictactoe server? This is similar strategy to online games where a server tracks only most secure information about player and the ones less important are kept inside client memory. The chances that the player exploits a client are way higher and so the server should not fully trust it.

Ok, so we know that perhaps we have to pwn tictactoc proxy server and then we have to trick the server into thinking that we won 100 games so it sends the flag to tictactoe which will forward it to us.

