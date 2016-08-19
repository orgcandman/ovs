/*
 * Copyright (c) 2016 Red Hat, Inc.
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

/* A non-exhaustive test for some of the functions and macros declared in
 * the change-utils suite in chutil.h. */

#include <config.h>
#undef NDEBUG

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "chutil.h"
#include "ovstest.h"
#include "random.h"
#include "util.h"

static int
get_mode(const char *pathname, mode_t *mode)
{
    struct stat st;
    if (stat(pathname, &st)) {
        return -1;
    }
    *mode = st.st_mode & 0x7ff;
    return 0;
}

static int
with_temp_file(int (*fn)(const char *pathname, int fd, bool usepath),
               bool usepath)
{
    char filepath[PATH_MAX] = "/tmp/test_chutil_wtfXXXXXX";
    mode_t old_mask = umask(0777);
    int fd = mkstemp(filepath);
    umask(old_mask);
    assert(fd >= 0);
    int result = fn(filepath, fd, usepath);
    close(fd);
    unlink(filepath);
    return result;
}

static int
with_temp_socket(int (*fn)(const char *pathname, int fd, bool usepath),
                 bool usepath)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    mode_t old_mask = umask(0777);
    char fname[PATH_MAX];
    int result = -1;

    assert(fd >= 0);

    /* keep attempting to open a socket until success */
    for (int kTimes = 0; kTimes < 10; ++kTimes) {
        struct sockaddr_un addr;
        snprintf(fname, PATH_MAX, "/tmp/test_chutil_socket%08X",
                 random_range(~0));
        memset(&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        snprintf((char *)&addr.sun_path, sizeof addr.sun_path, "%s", fname);
        if (!bind(fd, (struct sockaddr *)&addr, sizeof addr)) {
            result = fn(fname, fd, usepath);
            goto done;
        }
    }
    printf("E: Unable to open a socket after 10 attempts.\n");
done:
    umask(old_mask);
    unlink(fname);
    close(fd);
    return result;
}

static int
run_chmod_bad_parsing(const char *pathname, int fd, bool usepath)
{
    static char users[] = "bcdefhijklmnpqrstvwxyz";
    static char perms[] = "abcdefghijklmnopqtuvyz";
    static char actions[] = "~`!@#$%^&*()_";

    char *itest;

    mode_t pathmode;
    if (get_mode(pathname, &pathmode)) {
        return -1;
    }

    for (itest = users; itest != users + strlen(users); ++itest) {
        char buf[256] = {0};
        mode_t testmode;
        snprintf(buf, sizeof(buf), "%c+rwx", *itest);
        int chmodresult = usepath ? ovs_kchmod(pathname, buf) :
            ovs_fchmod(fd, buf);
        if (!chmodresult || get_mode(pathname, &testmode)
            || testmode != pathmode) {
            printf("F(%s)", buf);
            return -1;
        }
    }

    for (itest = perms; itest != perms + strlen(perms); ++itest) {
        char buf[256] = {0};
        mode_t testmode;
        snprintf(buf, sizeof(buf), "u+%c", *itest);
        int chmodresult = usepath ? ovs_kchmod(pathname, buf) :
            ovs_fchmod(fd, buf);
        if (!chmodresult || get_mode(pathname, &testmode)
            || testmode != pathmode) {
            printf("F(%s)", buf);
            return -1;
        }
    }

    for (itest = actions; itest != actions + strlen(actions); ++itest) {
        char buf[256] = {0};
        mode_t testmode;
        snprintf(buf, sizeof(buf), "u%crw", *itest);
        int chmodresult = usepath ? ovs_kchmod(pathname, buf) :
            ovs_fchmod(fd, buf);
        if (!chmodresult || get_mode(pathname, &testmode)
            || testmode != pathmode) {
            printf("F(%s)", buf);
            return -1;
        }
    }
    printf(".");
    return 0;
}

/* Skip suid and sgid for now. */
static int
run_chmod_str_successes(const char *pathname, int fd, bool usepath)
{
    const char *users[] = { "u", "g", "o", "a", "ug", "uo", "go" };
    const char *perms[] = { "r", "w", "x", "rw", "rx", "wx" };
    size_t iusers, iperms;
    mode_t chkmode;

    if (get_mode(pathname, &chkmode)) {
        return -1;
    }

    for (iusers = 0; iusers < ARRAY_SIZE(users); ++iusers) {
        for (iperms = 0; iperms < ARRAY_SIZE(perms); ++iperms) {
            mode_t pathmode;
            char buf[256] = {0};
            snprintf(buf, sizeof(buf), "%s+%s", users[iusers], perms[iperms]);
            int chmodresult = usepath ? ovs_kchmod(pathname, buf) :
                ovs_fchmod(fd, buf);
            if (chmodresult || get_mode(pathname, &pathmode)) {
                printf("run_chmod_successes:E(%s)\n", buf);
                return -1;
            }
            /* XXX: Check the actual mode here */
            snprintf(buf, sizeof(buf), "%s-%s", users[iusers], perms[iperms]);
            chmodresult = usepath ? ovs_kchmod(pathname, buf) :
                ovs_fchmod(fd, buf);
            if (chmodresult || get_mode(pathname, &pathmode)
                || pathmode != chkmode) {
                printf("run_chmod_successes:F(%s:%x:%x)\n", buf, pathmode,
                       chkmode);
                return -1;
            }
        }
    }

    mode_t pmode;
    int chmodchange = usepath ? ovs_kchmod(pathname, "u-rwx,g-rwx,o-rwx") :
        ovs_fchmod(fd, "u-rwx,g-rwx,o-rwx");
    if (chmodchange || get_mode(pathname, &pmode) || pmode != 0) {
        printf("run_chmod_successes:csvF\n");
        return -1;
    }

    chmodchange = usepath ? ovs_kchmod(pathname, "u=rx,g=w") :
        ovs_fchmod(fd, "u=rx,g=w");
    if (chmodchange || get_mode(pathname, &pmode)
        || pmode != (S_IRUSR | S_IXUSR | S_IWGRP)) {
        printf("run_chmod_successes:assignF\n");
        return -1;
    }
    return 0;
}

static int
run_chmod_numeric_successes(const char *pathname, int fd, bool usepath)
{
    const char *modestrs[] = {"0755", "0644", "0600", "11", "20", "755",
                              "640"};
    const mode_t expectedmode[] = {
        S_IRWXU | S_IRGRP | S_IROTH | S_IXGRP | S_IXOTH,
        S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR,
        S_IRUSR | S_IWUSR,
        S_IXOTH | S_IXGRP,
        S_IWGRP,
        S_IRWXU | S_IRGRP | S_IROTH | S_IXGRP | S_IXOTH,
        S_IRUSR | S_IRGRP | S_IWUSR,
    };
    size_t imodes;
    for (imodes = 0; imodes < ARRAY_SIZE(modestrs); ++imodes) {
        mode_t newmode;
        int chmodresult = usepath ? ovs_kchmod(pathname, modestrs[imodes]) :
            ovs_fchmod(fd, modestrs[imodes]);
        if (chmodresult || get_mode(pathname, &newmode)) {
            printf("run_chmod_numeric_successes:F(%s)\n", modestrs[imodes]);
            return -1;
        }
        if (newmode != expectedmode[imodes]) {
            printf("run_chmod_numeric_successes:F(%x:%x)\n", newmode,
                   expectedmode[imodes]);
            return -1;
        }
        if (ovs_fchmod(fd, "0000")) {
            printf("run_chmod_numeric_successes:E(%s)\n", modestrs[imodes]);
            return -1;
        }
    }
    return 0;
}

static int
run_ovs_strtouser_successes(void)
{
    /* seems this is the only user:group combination to exist? */
    const char *ugparses[] = {"root:", "root:root", "0:0", "0:", "nobody:",
                              "root", "nobody"};
    size_t iugstr;
    for (iugstr = 0; iugstr < ARRAY_SIZE(ugparses); ++iugstr) {
        uid_t ui = 1;
        gid_t gi = 1;
        char *user = NULL;
        if (ovs_strtousr(ugparses[iugstr], &ui, &user, &gi, true) ||
           !user || (strcmp("root", user) && strcmp("nobody", user))) {
            printf("run_ovs_strtouser_successes:F(%s)\n", ugparses[iugstr]);
            return -1;
        }
    }
    return 0;
}

static int
run_ovs_strtouser_failures(void)
{
    /* If any of these are successful, you have a poorly configured system
     * so this test 'failing' is the least of your worries. */
    const char *ugparses[] = {"nobody:root", "THISUSERBETTERNOTEXSIST:",
                              ":THISGROUPBETTERNOTEXIST"};
    size_t iugstr;
    for (iugstr = 0; iugstr < ARRAY_SIZE(ugparses); ++iugstr) {
        if (!ovs_strtousr(ugparses[iugstr], NULL, NULL, NULL, true)) {
            printf("run_ovs_strtouser_failures:F(%s)\n", ugparses[iugstr]);
            return -1;
        }
    }
    return 0;
}

static void
test_chutil_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    assert(!with_temp_file(run_chmod_bad_parsing, false));
    assert(!with_temp_file(run_chmod_str_successes, false));
    assert(!with_temp_file(run_chmod_numeric_successes, false));
    assert(!with_temp_file(run_chmod_str_successes, true));
    assert(!with_temp_file(run_chmod_numeric_successes, true));
    assert(!with_temp_socket(run_chmod_str_successes, true));
    assert(!with_temp_socket(run_chmod_numeric_successes, true));
    assert(!run_ovs_strtouser_successes());
    assert(!run_ovs_strtouser_failures());
    printf("\n");
}

OVSTEST_REGISTER("test-chutil", test_chutil_main);
