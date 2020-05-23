#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <assert.h>
#include <poll.h>
#include <linux/wait.h>
#include <sys/uio.h>
#include <linux/limits.h>
#include <time.h>
#include <sys/param.h>
#include <netinet/tcp.h>

#define __NR_pidfd_getfd 438
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct sockaddr_in *addr;

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
        errno = 0;
        return syscall(__NR_seccomp, op, flags, args);
}

static int sys_waitid(int which, pid_t pid, siginfo_t *info, int options,
                      struct rusage *ru)
{
        return syscall(__NR_waitid, which, pid, info, options, ru);
}

static inline int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int user_trap_syscall(int nr, unsigned int flags)
{
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
                        offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 1, 0),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (intptr_t)(addr), 1, 0),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        };

        struct sock_fprog prog = {
                .len = (unsigned short)ARRAY_SIZE(filter),
                .filter = filter,
        };

        return seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
}

static inline int sys_pidfd_getfd(int pidfd, int fd, int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, fd, flags);
}

int child(char *argv[]) {
	return execvpe(argv[1], &argv[1], environ);
}

int main(int argc, char *argv[])
{
	int ret, pid, pidfd, listener;
	struct seccomp_notif_resp resp;
	struct pollfd poll_fds[2] = {};
	struct seccomp_notif req;
	siginfo_t info = {
		.si_signo = 0,
	};

	addr = malloc(sizeof(*addr));
	assert(addr != NULL);

	listener = user_trap_syscall(__NR_connect, SECCOMP_FILTER_FLAG_NEW_LISTENER);
	assert(listener > 0);

	pid = fork();

	if (pid == 0) {
		return child(argv);
	}

	assert(pid > 0);

	pidfd = sys_pidfd_open(pid, 0);
	assert(pidfd > 0);

	poll_fds[0].fd = listener;
	poll_fds[0].events = POLLIN;

	poll_fds[1].fd = pidfd;
	poll_fds[1].events = POLLIN;

	srand(time(NULL));
	while (1) {
		int pidfd2, procfd, tgid, sock, flags;
		struct iovec local_iov, remote_iov;
		char procbuf[4096], path[PATH_MAX];
		char *cur;

		ret = poll(poll_fds, 2, -1);
		assert(ret > 0);

		if (poll_fds[1].revents & POLLIN) {
			ret = sys_waitid(P_PIDFD, pidfd, &info, WEXITED, NULL);
			return WEXITSTATUS(info.si_status);
		}

		memset(&req, 0, sizeof(req));
		assert(ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) == 0);

		memset(&resp, 0, sizeof(resp));
		resp.id = req.id;

		local_iov.iov_base = addr;
		local_iov.iov_len = sizeof(*addr);
		remote_iov.iov_base = (void*)req.data.args[1];
		remote_iov.iov_len = MIN(req.data.args[2], sizeof(*addr)) ;

		assert(process_vm_readv(req.pid, &local_iov, 1, &remote_iov, 1, 0) > 0);
		if (addr->sin_family != AF_INET || addr->sin_port != htons(2002) || addr->sin_addr.s_addr != 0x100007f) {
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			goto out;
		}

		addr->sin_port = htons(5000 + rand() % 4);

		/* Fetch the TID of the process */

		memset(&path, 0, sizeof(path));
		sprintf(path, "/proc/%d/status", req.pid);
		procfd = open(path, O_RDONLY);
		if (procfd == -1) {
			printf("Error (%s) while opening proc status %s", strerror(errno), procbuf);
			resp.val = -1;
			resp.error = -EAGAIN;
			goto out;
		}
		assert(read(procfd, &procbuf, sizeof(procbuf)) > 0);
		close(procfd);
		cur = strstr(procbuf, "Tgid:");
		cur += 6;
		tgid = atoi(cur);

		pidfd2 = sys_pidfd_open(tgid, 0);
		assert(pidfd2 > 0);

		sock = sys_pidfd_getfd(pidfd2, req.data.args[0], 0);
		assert(sock >= 0);
		close(pidfd2);

#ifdef MAGIC2
		flags = 1;
		assert(setsockopt(sock, SOL_TCP, TCP_NODELAY, (void*)&flags, sizeof(flags)) == 0);

		flags = 16000;
		assert(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (void*)&flags, sizeof(flags)) == 0);
		flags = 16000;
		assert(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (void*)&flags, sizeof(flags)) == 0);
#endif

		resp.val = connect(sock, addr, sizeof(*addr));
		close(sock);
		if (resp.val)
			resp.error = -1 * errno;
out:
		assert(ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0);
	}
}
