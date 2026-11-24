/* Round 9 providers-native: this kernel has no IPv6 (socket(AF_INET6) =
 * EAFNOSUPPORT), so an endpoint URL with an IPv6 literal cannot be reached.
 * This LD_PRELOAD shim lets a client "connect to [::1]:port": an AF_INET6
 * stream socket is created as AF_INET, and a connect to ::1 (or to a
 * v4-mapped address) goes to 127.0.0.1 on the same port. Everything above
 * the socket (URL parsing, TLS server name, certificate IP SAN matching)
 * still sees the IPv6 literal.
 *   gcc -O2 -Wall -shared -fPIC -o v6shim.so v6shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#define MAXFD 65536
static unsigned char faked[MAXFD];

int socket(int domain, int type, int protocol) {
    static int (*real)(int, int, int);
    if (!real) real = dlsym(RTLD_NEXT, "socket");
    if (domain == AF_INET6) {
        int fd = real(AF_INET, type, protocol);
        if (fd >= 0 && fd < MAXFD) faked[fd] = 1;
        if (getenv("V6SHIM_LOG")) fprintf(stderr, "v6shim: socket(AF_INET6) -> AF_INET fd %d\n", fd);
        return fd;
    }
    int fd = real(domain, type, protocol);
    if (fd >= 0 && fd < MAXFD) faked[fd] = 0;
    return fd;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real) real = dlsym(RTLD_NEXT, "connect");
    if (fd >= 0 && fd < MAXFD && faked[fd] && addr && addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        struct sockaddr_in a4;
        memset(&a4, 0, sizeof a4);
        a4.sin_family = AF_INET;
        a4.sin_port = a6->sin6_port;
        a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (getenv("V6SHIM_LOG")) fprintf(stderr, "v6shim: connect fd %d [v6]:%d -> 127.0.0.1\n", fd, ntohs(a6->sin6_port));
        return real(fd, (struct sockaddr *)&a4, sizeof a4);
    }
    return real(fd, addr, len);
}

int setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    static int (*real)(int, int, int, const void *, socklen_t);
    if (!real) real = dlsym(RTLD_NEXT, "setsockopt");
    if (fd >= 0 && fd < MAXFD && faked[fd] && level == IPPROTO_IPV6) return 0;
    return real(fd, level, name, val, len);
}
