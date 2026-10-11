#ifndef MUGVPN_SYS_H
#define MUGVPN_SYS_H

#include <sys/types.h>

/// Start `path` as uid/gid (no other groups), in `cwd`, with stdin from /dev/null,
/// stdout and stderr to `log_fd` and every other descriptor closed. The child
/// checks that root is gone for good before it runs anything. Returns the pid, or -1.
pid_t mugvpn_spawn_as(const char *path, char *const argv[], char *const envp[], const char *cwd,
                      int log_fd, uid_t uid, gid_t gid);

/// A new utun device (the kernel picks its number): its descriptor, its name in
/// `name` (at least 16 bytes). -1 on failure.
int mugvpn_open_utun(char *name, unsigned name_len);

/// Stop every process running as `uid` (not root), also those it forks meanwhile:
/// a child becomes `uid` and signals all of them until none is left. 0 when done.
int mugvpn_kill_uid(uid_t uid);

/// Remove `name` (a file, a link, or a folder with all in it) in the folder reached from `home` through `dirs`,
/// each step opened from the one before without following a link (none resolved again by path, so none swapped in
/// meanwhile is followed), never into another volume than the home's. 0: gone or never there; 1: left, the way (or
/// something in it) not one root may take: a link, a mounted volume; -1: stayed.
int mugvpn_remove_beneath(const char *home, const char *const dirs[], int ndirs, const char *name);

#endif
