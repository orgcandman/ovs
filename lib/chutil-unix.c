/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "chutil.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "daemon.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(chutil_unix);

#ifndef S_ISLNK
#define S_ISLNK(mode) (0)
#endif

#define USR_MODES (S_ISUID | S_IRWXU)
#define GRP_MODES (S_ISGID | S_IRWXG)
#define OTH_MODES (S_IRWXO)
#define ALL_MODES (USR_MODES | GRP_MODES | OTH_MODES)

#define READ_MODES  (S_IRUSR | S_IRGRP | S_IROTH)
#define WRITE_MODES (S_IWUSR | S_IWGRP | S_IWOTH)
#define EXEC_MODES  (S_IXUSR | S_IXGRP | S_IXOTH)

#define SUID_MODES  (S_ISUID | S_ISGID)

/* Convert a chown-style string to uid/gid; supports numeric arguments
 * as well as usernames. */
int
ovs_strtousr(const char *user_spec, uid_t *uid, char **user, gid_t *gid,
             bool validate_user_group)
{
    char *pos = strchr(user_spec, ':');
    size_t bufsize = 0;
    user_spec += strspn(user_spec, " \t\r\n");

    size_t len = pos ? pos - user_spec : strlen(user_spec);
    char *buf = NULL;
    struct passwd pwd, *res = NULL;
    int e;

    buf = x2nrealloc(NULL, &bufsize, sizeof pwd);
    char *user_search = NULL;
    uid_t uid_search = getuid();
    if (len) {
        user_search = xmemdup0(user_spec, len);
        if (!strcspn(user_search, "0123456789")) {
            uid_search = strtoul(user_search, NULL, 10);
            free(user_search);
            user_search = NULL;
        }
    }

    if (user_search) {
        while ((e = getpwnam_r(user_search, &pwd, buf,
                               bufsize * sizeof pwd, &res)) == ERANGE) {
            buf = x2nrealloc(buf, &bufsize, sizeof pwd);
        }
    } else {
        while ((e = getpwuid_r(uid_search, &pwd, buf, bufsize * sizeof pwd,
                               &res)) == ERANGE) {
            buf = x2nrealloc(buf, &bufsize, sizeof pwd);
        }
    }

    if (!res && !e) {
        e = ENOENT;
    }

    if (e) {
        VLOG_ERR("Failed to retrieve user pwentry (%s), aborting.",
                 ovs_strerror(e));
        goto release;
    }

    if (!user_search) {
        user_search = xstrdup(pwd.pw_name);
    }

    if (user) {
        *user = user_search;
    }

    if (uid) {
        *uid = pwd.pw_uid;
    }

    if (gid) {
        *gid = pwd.pw_gid;
    }

    if (pos) {
        gid_t tmpgid = pwd.pw_gid;
        char *grpstr = pos + 1;
        grpstr += strspn(grpstr, " \t\r\n");

        if (*grpstr) {
            struct group grp, *res;

            bufsize = 1;
            buf = x2nrealloc(buf, &bufsize, sizeof grp);

            if (strcspn(grpstr, "0123456789")) {
                while ((e = getgrnam_r(grpstr, &grp, buf,
                                       bufsize * sizeof grp, &res))
                       == ERANGE) {
                    buf = x2nrealloc(buf, &bufsize, sizeof grp);
                }
            } else {
                gid_t grpgid = strtoul(grpstr, NULL, 10);
                while ((e = getgrgid_r(grpgid, &grp, buf,
                                       bufsize * sizeof grp, &res))
                       == ERANGE) {
                    buf = x2nrealloc(buf, &bufsize, sizeof grp);
                }
            }

            if (!res && !e) {
                e = ENOENT;
            }

            if (e) {
                VLOG_ERR("Failed to get group entry for %s (%s), aborting.",
                         grpstr, ovs_strerror(e));
                goto release;
            }

            if (tmpgid != grp.gr_gid) {
                char **mem;

                for (mem = grp.gr_mem; *mem; ++mem) {
                    if (!strcmp(*mem, user_search)) {
                         break;
                     }
                }

                if (!*mem && validate_user_group) {
                    VLOG_ERR("Invalid user str %s (user %s is not in "
                             "group %s), aborting.", user_spec,
                             user_search, grpstr);
                    e = EINVAL;
                    goto release;
                }
                if (gid) {
                    *gid = grp.gr_gid;
                }
            }
        }
    }

release:
    free(buf);
    if (e || !user) {
        free(user_search);
    }
    return e;
}

/* Convert a chmod style string (or set of comma separated chmod style
 * strings) to a mode_t.
 */
static mode_t
chmod_getmode(const char *mode, mode_t oldmode)
{
    mode_t ret = oldmode & ALL_MODES;
    if (*mode >= '0' && *mode <= '7') {
        ret = 0;

        while (*mode >= '0' && *mode <= '7') {
            ret = (ret << 3) | (*mode++ - '0');
        }

        if (*mode) {
            errno = EINVAL;
            return 0;
        }
    } else {
        while (*mode) {
            mode_t actors_mask = 0, perms_mask = 0;
            char action = 0;
            while (*mode && !action) {
                switch (*mode++) {
                case 'a':
                    actors_mask |= ALL_MODES;
                    break;
                case 'u':
                    actors_mask |= USR_MODES;
                    break;
                case 'g':
                    actors_mask |= GRP_MODES;
                    break;
                case 'o':
                    actors_mask |= OTH_MODES;
                    break;
                case '+':
                case '-':
                case '=':
                    action = *(mode-1);
                    break;
                default:
                    errno = EINVAL;
                    return 0;
                }
            }
            if (!actors_mask) {
                actors_mask = USR_MODES;
            }
            while (*mode) {
                switch(*mode++) {
                case 'r':
                    perms_mask |= READ_MODES;
                    break;
                case 'w':
                    perms_mask |= WRITE_MODES;
                    break;
                case 'x':
                    perms_mask |= EXEC_MODES;
                    break;
                case 's':
                    perms_mask |= SUID_MODES;
                    break;
                case ',':
                    goto actions;
                default:
                    errno = EINVAL;
                    return 0;
                }
            }
actions:
            if (action == '+') {
                ret |= actors_mask & perms_mask;
            } else if (action == '-') {
                ret &= ~(actors_mask & perms_mask);
            } else if (action == '=') {
                ret &= ~(actors_mask & (READ_MODES | WRITE_MODES
                                        | EXEC_MODES));
                ret |= actors_mask & perms_mask;
            }
        }
    }
    return ret;
}


#define K_ROUNDS 9 /* Lifted from "Portably Solving File TOCTTOU Races with
                      Hardness Amplification" by Tsafrir, et. al. */

static int cmp_stat(struct stat *s1, struct stat *s2)
{
    return s1->st_ino == s2->st_ino && s1->st_dev == s2->st_dev &&
        s1->st_mode == s2->st_mode;
}


/* Checks whether the relative path element is a symlink.  If an error
 * occurs, returns -1.  If the path is a symlink, returns 1.  Otherwise,
 * returns 0.  The stat struct, and target, are output variables and are
 * considered valid unless the return value is -1.  In the case that the
 * hardness Amplification fails, errno will be set to EBADFD. */
static int is_symlink(int dirfd, const char *path_elem, char target[],
                      size_t target_len, struct stat *s)
{
    struct stat s_cmp;
    int result;
    for (int k = 0; k < K_ROUNDS; ++k) {
        result = fstatat(dirfd, path_elem, s, 0);
        if (!k) {
            s_cmp = *s;
        } else if (!cmp_stat(&s_cmp, s)){
            return -1;
        }
    }

    if (!result && S_ISLNK(s->st_mode)) {
        result = readlinkat(dirfd, path_elem, target, target_len);
        if (result != -1) {
            target[result] = '\0';
            result = 1;
        }
    }
    return result;
}


static int directory_traverse(const char *path, int top_fd)
{
    char *dir_path = NULL, *full_path = NULL;
    int dirfd = -1;
    struct stat st;

    if (path[0] != '/' && top_fd == -1) {
        char cwd_buf[PATH_MAX] = {0};
        if (getcwd(cwd_buf, PATH_MAX)) {
            top_fd = directory_traverse(cwd_buf, -1);
        }
    } else {
        top_fd = open("/", O_PATH);
    }

    if (top_fd == -1 || !strcmp(path, "/")) {
        return top_fd;
    }

    dir_path = full_path = xstrdup(path);
    dir_path += strspn(dir_path, "/");
    do {
        char symlink_target[PATH_MAX] = {0};
        if (strspn(dir_path, "/")) {
            *(dir_path + strspn(dir_path, "/")) = '\0';
        }
        switch (is_symlink(top_fd, dir_path, symlink_target, PATH_MAX, &st)) {
        case 0:
            dirfd = openat(top_fd, dir_path, O_PATH|O_NOFOLLOW|O_DIRECTORY);
            break;
        case 1:
            if (symlink_target[0] != '/') {
                dirfd = directory_traverse(symlink_target, top_fd);
            } else {
                dirfd = directory_traverse(symlink_target, -1);
            }
            break;
        default:
            dirfd = -1;
            break;
        }
        close(top_fd);
        if (dirfd != -1) {
            struct stat s;
            if (!fstat(dirfd, &s) && cmp_stat(&s, &st)) {
                size_t path_elem_len = strlen(dir_path);
                dir_path += path_elem_len;
            } else {
                close(dirfd);
                dirfd = -1;
            }
        }
        top_fd = dirfd;
    } while (dirfd >= 0 && strlen(dir_path));
    free(full_path);
    return top_fd;
}


/* Changes the mode of a file to the mode specified.  Accepts chmod style
 * comma-separated strings.  Returns 0 on success, otherwise a positive errno
 * value.  This version partially implements the amplification hardness
 * technique to detect (and occasionally prevent) some forms of TOCTTOU
 * errors.  In the case that the named file is a unix-domain socket, the
 * containing directory for the socket must have restrictive permissions.
 * EINVAL will be populated in errno if the final path atom is a symbolic link.
 * It is recommended to use ovs_fchmod if the path is already opened. */
int
ovs_kchmod(const char *path, const char *mode)
{
    char *tmpdir = xstrdup(path);
    char *tmppath = strrchr(tmpdir, '/');
    int fd = -1, result = 0;
    int dirfd, k;
    char target_path[PATH_MAX];
    struct stat st, s;
    if (!tmppath) {
        dirfd = directory_traverse(".", -1);
    } else {
        *tmppath++ = '\0';
        dirfd = directory_traverse(tmpdir, -1);
    }

    if (dirfd == -1 || is_symlink(dirfd, tmppath, target_path, PATH_MAX, &s)) {
        goto end;
    }

    mode_t new_mode;
    errno = 0;
    new_mode = chmod_getmode(mode, s.st_mode);
    result = fchmodat(dirfd, tmppath, new_mode, 0);
    /* need to reset 's' copy of st_mode, because it will have changed. */
    s.st_mode = new_mode | (s.st_mode & ~(ALL_MODES));
    for (k = 0; !errno && !result && k < K_ROUNDS; ++k) {
        result = fstatat(dirfd, tmppath, &st, AT_SYMLINK_NOFOLLOW);
        if (result) {
            goto end;
        }

        if (!cmp_stat(&s, &st)) {
            /* WARNING: In this case, a race means we modified an inode,
             * and it may have been the wrong one. */
            errno = EBADFD;
            goto end;
        }
    }

end:
    if (errno) {
        result = errno;
        VLOG_ERR("ovs_kchown: (%s)", ovs_strerror(errno));
    }
    if (fd != -1) {
        close(fd);
    }
    if (dirfd != -1) {
        close(dirfd);
    }
    free(tmpdir);
    return result;
}


/* Changes the mode of a file to the mode specified.  Accepts chmod style
 * comma-separated strings.  Returns 0 on success, otherwise a positive errno
 * value.  This version partially implements the amplification hardness
 * technique to detect (and occasionally prevent) some forms of TOCTTOU
 * errors.  In the case that the named file is a unix-domain socket, the
 * containing directory for the socket must have restrictive permissions.  In
 * the case of a normal file, an openat(directory fd, filename,
 * O_PATH|O_NOFOLLOW) call is used to get a guaranteed inode mapping, and then
 * the ovs_fchmod call is used.  EINVAL will be populated in errno if the
 * final path atom is a symbolic link. */
int
ovs_kchown(const char *path, const char *usrstr)
{
    char *tmpdir = xstrdup(path);
    char *tmppath = strrchr(tmpdir, '/');
    int fd = -1, result = 0;
    int dirfd, k;
    char target_path[PATH_MAX];
    struct stat st, s;
    if (!tmppath) {
        dirfd = directory_traverse(".", -1);
    } else {
        *tmppath++ = '\0';
        dirfd = directory_traverse(tmpdir, -1);
    }

    if (dirfd == -1 || is_symlink(dirfd, tmppath, target_path, PATH_MAX, &s)) {
        goto end;
    }

    uid_t user;
    gid_t group;

    if (ovs_strtousr(usrstr, &user, NULL, &group, true)) {
        errno = EINVAL;
        goto end;
    }

    errno = 0; /* clearing errno here is for the result assignment later. */
    result = fchownat(dirfd, tmppath, user, group, 0);
    for (k = 0; !errno && !result && k < K_ROUNDS; ++k) {
        result = fstatat(dirfd, tmppath, &st, AT_SYMLINK_NOFOLLOW);
        if (result) {
            goto end;
        }

        if (!cmp_stat(&s, &st)) {
            /* WARNING: In this case, a race means we modified an inode,
             * and it may have been the wrong one. */
            errno = EBADFD;
            goto end;
        }
    }

end:
    if (errno) {
        result = errno;
        VLOG_ERR("ovs_kchown: (%s)", ovs_strerror(errno));
    }

    if (fd != -1) {
        close(fd);
    }
    if (dirfd != -1) {
        close(dirfd);
    }
    free(tmpdir);
    return result;
}


/* Changes the mode of a file to the mode specified.  Accepts chmod style
 * comma-separated strings.  Returns 0 on success, otherwise a positive errno
 * value. */
int
ovs_fchmod(int fd, const char *mode)
{
    mode_t new_mode;
    struct stat st;

    if (fstat(fd, &st)) {
        VLOG_ERR("ovs_fchown: fstat (%s)", ovs_strerror(errno));
        return errno;
    }

    errno = 0;
    new_mode = chmod_getmode(mode, st.st_mode);
    if (errno) {
        VLOG_ERR("ovs_fchmod bad mode (%s) specified (%s)", mode,
                 ovs_strerror(errno));
        return errno;
    }

    if (fchmod(fd, new_mode)) {
        VLOG_ERR("ovs_fchmod: chmod error (%s) with mode %s",
                 ovs_strerror(errno), mode);
        return errno;
    }
    return 0;
}


/* Changes the ownership of a file to the mode specified.  Accepts chown style
 * user:group strings.  Returns 0 on success.  Non-zero results contain
 * errno. */
int
ovs_fchown(int fd, const char *owner)
{
    uid_t user;
    gid_t group;

    if (ovs_strtousr(owner, &user, NULL, &group, true)) {
        VLOG_ERR("ovs_fchown: unknown user or group - bailing");
        return errno;
    }

    if (fchown(fd, user, group)) {
        VLOG_ERR("ovs_fchown: chown error (%s)", ovs_strerror(errno));
        return errno;
    }

    return 0;
}
