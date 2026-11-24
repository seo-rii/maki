/* LD_PRELOAD shim for nbdkit + the Maki plugin: logs every operation that
 * changes a file or directory on the filesystem holding PLSHIM_ROOT (use a
 * dedicated tmpfs), with payloads and CLOCK_MONOTONIC timestamps, to
 * PLSHIM_LOG. plreplay.py rebuilds power-loss images from the log.
 *
 * One global mutex covers "real call + log record", so the log is a
 * linearization of the calls and a timestamp is taken after the call
 * returned. Optional fault injection (PLSHIM_FAULT, see below).
 *
 * build: gcc -O2 -shared -fPIC -o plshim.so plshim.c -ldl -lpthread
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int log_fd = -1;
static dev_t root_dev;
static int active;

/* fault injection: PLSHIM_FAULT="sync=P,write=P,seed=N,enospc=P,after=K"
 *   sync:  probability that fdatasync/fsync on a regular file fails with EIO
 *          (the real sync is NOT performed; record 'X')
 *   write: probability that pwrite fails with EIO after writing a prefix
 *   after: no fault before this many logged operations */
static double p_sync, p_write, p_dsync, p_trunc, p_alloc, p_unlink;
static int werrno = EIO;
static uint64_t rng_state = 88172645463325252ULL;
static long fault_after, nops;
static const char *fault_gate;   /* PLSHIM_FAULT_GATE: faults only while this path exists */

static uint64_t rnd(void) {
  rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
  return rng_state;
}
static int chance(double p) {
  if (p <= 0 || nops < fault_after) return 0;
  if (fault_gate && syscall(SYS_faccessat, AT_FDCWD, fault_gate, F_OK) != 0) return 0;
  return (double)(rnd() >> 11) / (double)(1ULL << 53) < p;
}

struct rec {
  char type; char pad[3];
  uint32_t len;      /* payload bytes */
  uint64_t ts;       /* CLOCK_MONOTONIC ns, after the call */
  uint64_t ino;
  uint64_t a, b;
};

static uint64_t now_ns(void) {
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void emit(char type, uint64_t ino, uint64_t a, uint64_t b, const void *payload, uint32_t len) {
  struct rec r; memset(&r, 0, sizeof r);
  r.type = type; r.len = len; r.ts = now_ns(); r.ino = ino; r.a = a; r.b = b;
  struct iovec iov[2] = {{&r, sizeof r}, {(void *)payload, len}};
  ssize_t n = syscall(SYS_writev, log_fd, iov, len ? 2 : 1);
  if (n != (ssize_t)(sizeof r + len)) { static const char m[] = "plshim: short log write\n"; syscall(SYS_write, 2, m, sizeof m - 1); abort(); }
  nops++;
}

__attribute__((constructor)) static void init(void) {
  const char *root = getenv("PLSHIM_ROOT"), *log = getenv("PLSHIM_LOG"), *fault = getenv("PLSHIM_FAULT");
  struct stat st;
  if (!root || !log || stat(root, &st) != 0) return;
  root_dev = st.st_dev;
  log_fd = syscall(SYS_openat, AT_FDCWD, log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (log_fd < 0) return;
  fault_gate = getenv("PLSHIM_FAULT_GATE");
  if (fault) {
    const char *p;
    if ((p = strstr(fault, "sync=")) && (p == fault || p[-1] == ',')) p_sync = atof(p + 5);
    if ((p = strstr(fault, "dsync="))) p_dsync = atof(p + 6);
    if ((p = strstr(fault, "trunc="))) p_trunc = atof(p + 6);
    if ((p = strstr(fault, "alloc="))) p_alloc = atof(p + 6);
    if ((p = strstr(fault, "unlink="))) p_unlink = atof(p + 7);
    if ((p = strstr(fault, "werrno="))) werrno = atoi(p + 7);
    if ((p = strstr(fault, "write="))) p_write = atof(p + 6);
    if ((p = strstr(fault, "seed="))) rng_state ^= strtoull(p + 5, NULL, 10) * 0x9E3779B97F4A7C15ULL;
    if ((p = strstr(fault, "after="))) fault_after = atol(p + 6);
  }
  active = 1;
}

/* 1 regular file on the root device, 2 directory there, 0 otherwise */
static int tracked(int fd, struct stat *st) {
  if (!active) return 0;
  if (fstat(fd, st) != 0 || st->st_dev != root_dev) return 0;
  if (S_ISREG(st->st_mode)) return 1;
  if (S_ISDIR(st->st_mode)) return 2;
  return 0;
}

#define REAL(name) static __typeof__(name) *real; if (!real) real = dlsym(RTLD_NEXT, #name)

/* ---- data ---------------------------------------------------------------- */
static ssize_t do_pwrite(int fd, const void *buf, size_t n, off_t off) {
  struct stat st;
  if (tracked(fd, &st) != 1) return syscall(SYS_pwrite64, fd, buf, n, off);
  pthread_mutex_lock(&mu);
  ssize_t r;
  if (n > 1024 && chance(p_write)) {
    size_t part = (rnd() % (n / 512)) * 512;   /* a persisted prefix, then EIO */
    r = part ? syscall(SYS_pwrite64, fd, buf, part, off) : 0;
    if (r > 0) emit('W', st.st_ino, off, 1, buf, (uint32_t)r);
    pthread_mutex_unlock(&mu);
    errno = werrno;
    return -1;
  }
  r = syscall(SYS_pwrite64, fd, buf, n, off);
  int e = errno;
  if (r > 0) emit('W', st.st_ino, off, 0, buf, (uint32_t)r);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) { return do_pwrite(fd, buf, n, off); }
ssize_t pwrite64(int fd, const void *buf, size_t n, off64_t off) { return do_pwrite(fd, buf, n, off); }

ssize_t write(int fd, const void *buf, size_t n) {
  struct stat st;
  if (tracked(fd, &st) != 1) return syscall(SYS_write, fd, buf, n);
  pthread_mutex_lock(&mu);
  off_t off = lseek(fd, 0, SEEK_CUR);
  ssize_t r = syscall(SYS_write, fd, buf, n);
  int e = errno;
  if (r > 0) emit('W', st.st_ino, off, 0, buf, (uint32_t)r);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}

static int do_sync(int fd, long nr) {
  struct stat st;
  int k = tracked(fd, &st);
  if (!k) return syscall(nr, fd);
  pthread_mutex_lock(&mu);
  if (k == 1 && chance(p_sync)) {
    emit('X', st.st_ino, 0, 0, NULL, 0);
    pthread_mutex_unlock(&mu);
    errno = EIO;
    return -1;
  }
  if (k == 2 && chance(p_dsync)) {   /* directory sync fails: nothing recorded */
    nops++;
    pthread_mutex_unlock(&mu);
    errno = EIO;
    return -1;
  }
  int r = syscall(nr, fd);
  int e = errno;
  if (r == 0) emit(k == 1 ? 'S' : 'D', st.st_ino, 0, 0, NULL, 0);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int fdatasync(int fd) { return do_sync(fd, SYS_fdatasync); }
int fsync(int fd) { return do_sync(fd, SYS_fsync); }

static int do_ftruncate(int fd, off_t len) {
  struct stat st;
  if (tracked(fd, &st) != 1) return syscall(SYS_ftruncate, fd, len);
  pthread_mutex_lock(&mu);
  if (chance(p_trunc)) { nops++; pthread_mutex_unlock(&mu); errno = EIO; return -1; }
  int r = syscall(SYS_ftruncate, fd, len);
  int e = errno;
  if (r == 0) emit('T', st.st_ino, len, 0, NULL, 0);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int ftruncate(int fd, off_t len) { return do_ftruncate(fd, len); }
int ftruncate64(int fd, off64_t len) { return do_ftruncate(fd, len); }

static int do_fallocate(int fd, int mode, off_t off, off_t len) {
  struct stat st;
  if (tracked(fd, &st) != 1) return syscall(SYS_fallocate, fd, mode, off, len);
  pthread_mutex_lock(&mu);
  if (chance(p_alloc)) { nops++; pthread_mutex_unlock(&mu); errno = (mode & FALLOC_FL_PUNCH_HOLE) ? EIO : ENOSPC; return -1; }
  int r = syscall(SYS_fallocate, fd, mode, off, len);
  int e = errno;
  if (r == 0) emit((mode & FALLOC_FL_PUNCH_HOLE) ? 'H' : 'A', st.st_ino, off, len, NULL, 0);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int fallocate(int fd, int mode, off_t off, off_t len) { return do_fallocate(fd, mode, off, len); }
int fallocate64(int fd, int mode, off64_t off, off64_t len) { return do_fallocate(fd, mode, off, len); }
int posix_fallocate(int fd, off_t off, off_t len) { int r = do_fallocate(fd, 0, off, len); return r == 0 ? 0 : errno; }
int posix_fallocate64(int fd, off64_t off, off64_t len) { int r = do_fallocate(fd, 0, off, len); return r == 0 ? 0 : errno; }

/* ---- namespace ----------------------------------------------------------- */
/* parent directory inode and last component of dirfd-relative `path` */
static int parent_of(int dirfd, const char *path, struct stat *pst, const char **name) {
  const char *slash = strrchr(path, '/');
  if (!slash) {
    *name = path;
    if (dirfd == AT_FDCWD) return stat(".", pst);
    return fstat(dirfd, pst);
  }
  char dir[4096];
  size_t n = (size_t)(slash - path);
  if (n >= sizeof dir) return -1;
  memcpy(dir, path, n); dir[n] = 0;
  *name = slash + 1;
  return fstatat(dirfd, n ? dir : "/", pst, 0);
}

static void log_link(char type, int dirfd, const char *path) {
  struct stat pst, cst; const char *name;
  if (!active || parent_of(dirfd, path, &pst, &name) != 0 || pst.st_dev != root_dev) return;
  if (fstatat(dirfd, path, &cst, AT_SYMLINK_NOFOLLOW) != 0) return;
  emit(type, pst.st_ino, cst.st_ino, S_ISDIR(cst.st_mode), name, (uint32_t)strlen(name));
}

static int do_openat(int dirfd, const char *path, int flags, mode_t mode) {
  if (!active || !(flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
    return syscall(SYS_openat, dirfd, path, flags, mode);
  pthread_mutex_lock(&mu);
  int r = syscall(SYS_openat, dirfd, path, flags, mode);
  int e = errno;
  if (r >= 0) log_link('C', dirfd, path);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int openat(int dirfd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
  return do_openat(dirfd, path, flags, mode);
}
int openat64(int dirfd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
  return do_openat(dirfd, path, flags, mode);
}
int open(const char *path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
  return do_openat(AT_FDCWD, path, flags, mode);
}
int open64(const char *path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
  return do_openat(AT_FDCWD, path, flags, mode);
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
  if (!active) return syscall(SYS_linkat, olddirfd, oldpath, newdirfd, newpath, flags);
  pthread_mutex_lock(&mu);
  int r = syscall(SYS_linkat, olddirfd, oldpath, newdirfd, newpath, flags);
  int e = errno;
  if (r == 0) log_link('C', newdirfd, newpath);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}

static int do_mkdirat(int dirfd, const char *path, mode_t mode) {
  if (!active) return syscall(SYS_mkdirat, dirfd, path, mode);
  pthread_mutex_lock(&mu);
  int r = syscall(SYS_mkdirat, dirfd, path, mode);
  int e = errno;
  if (r == 0) log_link('C', dirfd, path);
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int mkdirat(int dirfd, const char *path, mode_t mode) { return do_mkdirat(dirfd, path, mode); }
int mkdir(const char *path, mode_t mode) { return do_mkdirat(AT_FDCWD, path, mode); }

static int do_unlinkat(int dirfd, const char *path, int flags) {
  struct stat pst; const char *name;
  if (!active || parent_of(dirfd, path, &pst, &name) != 0 || pst.st_dev != root_dev)
    return syscall(SYS_unlinkat, dirfd, path, flags);
  pthread_mutex_lock(&mu);
  if (chance(p_unlink)) { nops++; pthread_mutex_unlock(&mu); errno = EIO; return -1; }
  int r = syscall(SYS_unlinkat, dirfd, path, flags);
  int e = errno;
  if (r == 0) emit('U', pst.st_ino, 0, 0, name, (uint32_t)strlen(name));
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int unlinkat(int dirfd, const char *path, int flags) { return do_unlinkat(dirfd, path, flags); }
int unlink(const char *path) { return do_unlinkat(AT_FDCWD, path, 0); }
int rmdir(const char *path) { return do_unlinkat(AT_FDCWD, path, AT_REMOVEDIR); }

static int do_renameat(int od, const char *op, int nd, const char *np, unsigned flags) {
  struct stat ost, nst; const char *oname, *nname;
  if (!active || parent_of(od, op, &ost, &oname) != 0 || parent_of(nd, np, &nst, &nname) != 0 ||
      (ost.st_dev != root_dev && nst.st_dev != root_dev))
    return syscall(SYS_renameat2, od, op, nd, np, flags);
  pthread_mutex_lock(&mu);
  int r = syscall(SYS_renameat2, od, op, nd, np, flags);
  int e = errno;
  if (r == 0) {
    char buf[1024];
    size_t a = strlen(oname), b = strlen(nname);
    if (a + b + 1 < sizeof buf) {
      memcpy(buf, oname, a); buf[a] = 0; memcpy(buf + a + 1, nname, b);
      emit('R', ost.st_ino, nst.st_ino, flags, buf, (uint32_t)(a + 1 + b));
    }
  }
  pthread_mutex_unlock(&mu);
  errno = e;
  return r;
}
int renameat(int od, const char *op, int nd, const char *np) { return do_renameat(od, op, nd, np, 0); }
int renameat2(int od, const char *op, int nd, const char *np, unsigned flags) { return do_renameat(od, op, nd, np, flags); }
int rename(const char *op, const char *np) { return do_renameat(AT_FDCWD, op, AT_FDCWD, np, 0); }
