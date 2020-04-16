# sandbox-caas (sandbox, net namespace, sockets, shellcode)
I havn't fully solved the challenge myself. I've got stack on ReceiveFD implementation in assembly which just wasn't working for some reasons.
After few hours I gave up and started looking for some other implementations and found [this](https://ctftime.org/writeup/15869) cool writeup which used some g++ flags and objcopy to extract shellcode from c. I have copied the assembly part of the code. 


## Infrastructure
As a user we can connect to the challenge server. It will ask us to provide the binary which we want to execute (shellcode). This binary will be run in a custom sandbox based on linux namespaces, rlimit and seccomp.

![](img/infra.png)

Moreover we know that on same machine there are two other services running. One listening on localhost:8080 being a metadata server and one listening on localhost:6666 being a flag server.

## Flag Server
There is nothing tricky about flag server. When client connects to it, it will just send him the flag. So the goal is quite obvious – we need to connect to the Flag Server.

## Metadata Server
It seems that metadata server havn't been yet finished. When connecting to it, it just responds with 'Not implemented' message.

## RPC Server
RPC Server is a bridge between the sandboxed process and the rest of the world. They communicate using a pipe (descriptor 100). The sandboxed process can for example ask RPC Server to connect to Metadata Server for him.

## Sandbox
You might wonder, why sandboxed process needs to ask RPC Server to connect him with Metadata Server. Well, the sandbox is quite restrictive and sandboxed process is placed in new NET_NAMESPACE, meaning he won't see any network interfaces of the host.

Sandbox details:
i) The process is placed in new new, ipc, cgroups, user, uts, pid, mount namespaces.
ii) The process has no capabilities.
iii) The pivot_root was invoked before passing control to our shellcode and so, the process root is in an empty tmpfs folder /tmp/.challenge/. The old root was umounted.
iv) Seccomp policy allows only: read, write, close, munmap, sched_yield, dup, dup2, nanosleep, connect, accept, recvmsg, bind, exit, exit_group, clone, mmap syscalls.
iv) The proces memory maps have been unmaped, leaving only the stack and user shellcode.

## API
Reading through sandbox details it is quite obvious that it is rather decent sandbox and perhaps the weak point is this RPC Server. Let's check it closer.
The RPC Server works in an infinite loop:

```c
void Server(pid_t pid, int comms_fd) {
  Request req;
  while (true) {
    Response res;
    int fd_to_send = -1;

    if (TEMP_FAILURE_RETRY(read(comms_fd, &req, sizeof(req))) != sizeof(req)) {
      return;
    }

    // Validate request parameters.
    if (!ValidateRequest(pid, req)) {
      fprintf(stderr, "Request validation failed.\n");
      return;
    }

    // Parameters good, actually execute the request.
    if (!ExecuteRequest(pid, req, &res, &fd_to_send)) {
      return;
    }

    if (TEMP_FAILURE_RETRY(write(comms_fd, &res, sizeof(res))) != sizeof(res)) {
      return;
    }

    if (fd_to_send != -1) {
      if (!SendFD(comms_fd, fd_to_send)) {
        return;
      }
      close(fd_to_send);
    }
  }
}
```

It reads a request from a sandboxed process, then it checks if the request is valid. If the request is valid, it executes it. Finally it sends a reply to the process and when needed also a file descriptor. 

There are two types of requests that a sandboxed process can send, but only one – ConnectToMetadataServerRequest is interesting (the other one – GetEnvironmentDataRequest is just not yet implemented). 

So let's check out ConnectToMetadataServerRequest.

![](img/conn.png)