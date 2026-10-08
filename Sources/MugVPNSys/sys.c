#include "MugVPNSys.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>
#include <net/if_utun.h>

pid_t mugvpn_spawn_as(const char *path, char *const argv[], char *const envp[], const char *cwd,
                      int log_fd, uid_t uid, gid_t gid) {
    if (uid == 0 || gid == 0) return -1;
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd < 0) return -1;
    // Every descriptor the helper could have, not only those under the soft limit.
    int max_fd = getdtablesize();
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY && rl.rlim_max > (rlim_t)max_fd)
        max_fd = rl.rlim_max > 1 << 20 ? 1 << 20 : (int)rl.rlim_max;
    else if (max_fd < 1 << 16)
        max_fd = 1 << 16;
    pid_t pid = fork();
    if (pid != 0) {
        close(null_fd);
        return pid;
    }
    // The child: only async-signal-safe calls from here on. No signal the helper
    // ignores or blocks (it ignores SIGTERM) stays so for openvpn; its own session.
    for (int sig = 1; sig < NSIG; sig++) signal(sig, SIG_DFL);
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
    setsid();
    if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0) _exit(126);
    if (setuid(0) == 0 || getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) _exit(126);
    if (chdir(cwd) != 0) _exit(126);
    // A process of its own, no more (it forks nothing); no core dumps; a bounded log.
    struct rlimit one = { 1, 1 }, no_core = { 0, 0 }, log_size = { 32 << 20, 32 << 20 }, files = { 1024, 1024 };
    if (setrlimit(RLIMIT_NPROC, &one) != 0 || setrlimit(RLIMIT_CORE, &no_core) != 0 || setrlimit(RLIMIT_FSIZE, &log_size) != 0
        || setrlimit(RLIMIT_NOFILE, &files) != 0)
        _exit(126);
    if (dup2(null_fd, 0) < 0 || dup2(log_fd, 1) < 0 || dup2(log_fd, 2) < 0) _exit(126);
    for (int fd = 3; fd < max_fd; fd++) close(fd);
    execve(path, argv, envp);
    _exit(127);
}

int mugvpn_open_utun(char *name, unsigned name_len) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;  // the next free utun
    socklen_t len = name_len;
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) goto fail;
    addr.sc_id = info.ctl_id;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto fail;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len) < 0) goto fail;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
fail:
    close(fd);
    return -1;
}

int mugvpn_kill_uid(uid_t uid) {
    if (uid == 0) return -1;
    int max_fd = getdtablesize();
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // Nothing of the helper's (its utun copies, sockets) goes along as the target id.
        for (int fd = 3; fd < max_fd; fd++) close(fd);
        if (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid(uid) != 0 || setuid(0) == 0) _exit(2);
        // kill(-1) from this id: every process of it but this one. Again until none answers
        // (the killed stay zombies until launchd reaps them, and they answer meanwhile).
        for (int i = 0; i < 500; i++) {
            if (kill(-1, SIGKILL) != 0 && errno == ESRCH) _exit(0);
            usleep(10000);
        }
        _exit(1);
    }
    // The target id could stop the child: never waited for more than a few seconds.
    int status = 0;
    for (int i = 0; i < 600; i++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (r < 0 && errno != EINTR) return -1;
        usleep(10000);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return -1;
}
