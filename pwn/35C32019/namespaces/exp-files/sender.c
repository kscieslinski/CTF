#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <string.h>
#include <fcntl.h>


#define RCV_NAME "rcv_name"
#define SND_NAME "snd_name"


int connect_to_receiver() {
    /* Create named socked in abstract namespace, as sandboxes doesn't share file system. */
    int snd_sk = socket(AF_UNIX, SOCK_STREAM, 0);
    if (snd_sk == -1) {
        printf("[!] socket failed\n");
        return -1;
    }


    /* Bind abstract socket. The snd_addr.sun_path[0] must be null byte to indicate this is an abstract socket. */
    struct sockaddr_un snd_addr;
    memset(&snd_addr, 0x0, sizeof(struct sockaddr_un));
    strncpy(&snd_addr.sun_path[1], SND_NAME, strlen(SND_NAME) + 1);
    snd_addr.sun_family = AF_UNIX;

    if (bind(snd_sk, (struct sockaddr*) &snd_addr, sizeof(sa_family_t) + strlen(SND_NAME) + 1) == -1) {
        printf("[!] bind failed\n");
        return -1;
    }

    /* Send message to receiver. */
    struct sockaddr_un rcv_addr;
    memset(&rcv_addr, 0x0, sizeof(struct sockaddr_un));
    strncpy(&rcv_addr.sun_path[1], RCV_NAME, strlen(RCV_NAME) + 1);
    rcv_addr.sun_family = AF_UNIX;

    /* First connect to receicer. */
    if (connect(snd_sk, (struct sockaddr*) &rcv_addr, sizeof(sa_family_t) + strlen(RCV_NAME) + 1) == -1) {
        perror("[!] connect failed");
        return -1;
    }

    return snd_sk;
}

int send_fd(int sk, int fd) {
    printf("[i] Sending by sk: %d, fd: %d\n", sk, fd);
    struct msghdr msg = {0};
    
    char iobuf[1];
    struct iovec io = {
        .iov_base = iobuf,
        .iov_len = sizeof(iobuf)
    };
    /* Ancillary data buffer, wrapped in a union in order to ensure it is suitably aligned */
    union {
        char buf[CMSG_SPACE(sizeof(fd))];
        struct cmsghdr align;
    } u;

    msg.msg_iov = &io; 
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = CMSG_LEN(sizeof(fd));

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    *((int *) CMSG_DATA(cmsg)) = fd;
    
    if (sendmsg(sk, &msg, 0) == -1) {
        perror("[!] sendmsg");
        return -1;
    }

    return 0;
}

int send_fd_to_receiver(int fd) {
    int snd_sk = connect_to_receiver();
    if (snd_sk == -1) {
        return -1;
    }

    if (send_fd(snd_sk, fd) == -1) {
        return -1;
    }
    return 0;
}


int main() {
    /* Print some debug information about sender process. */
    printf("[i] My pid: %d\n", getpid());

    /* Send file descriptor to sender's chroot directory: /tmp/chroots/<sender sandbox idx>. */
    int dir_fd = open("/", O_DIRECTORY | O_RDONLY, 0);
    if (dir_fd == -1) {
        perror("[!] open failed");
        return -1;
    }

    if (send_fd_to_receiver(dir_fd) == -1) {
        return -1;
    }
    close(dir_fd);


    return 0;
}