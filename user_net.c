#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <linux/genetlink.h>
#include <pthread.h>
#include <syscall.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int waitflag;

void* kernel_callback_function()
{
	int retval = 0;

    /* Read message from kernel */
    recvmsg(sock_fd, &msg, 0);
	
	retval = -1 * (*((int*)NLMSG_DATA(nlh)));

	errno = retval;

	if (0 != retval) {
		printf("TID = %ld -", syscall(SYS_gettid));
		perror(" Error occured");
	}
	else {
		printf("TID = %ld -", syscall(SYS_gettid));
		printf(" Success\n");
	}

	waitflag++;
//	__sync_add_and_fetch((waitflag), 1);

	if(1 != waitflag);
		exit(-1);

    close(sock_fd);
    return NULL;
}
int create_socket(int unique_id)
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = unique_id;

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);

	/*	This value should be same as src_addr.nl_pid for the message to be
		recevied. Also if we want different threads to create different netlink
		sockets then we should change this value for each thread and expects its
		callback
	*/
    nlh->nlmsg_pid = unique_id;
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

	return 0;
}
