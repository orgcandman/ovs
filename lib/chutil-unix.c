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
