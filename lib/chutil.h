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

#ifndef CHUTIL_H
#define CHUTIL_H 1

#include <stdbool.h>
#include <sys/types.h>

#include "compiler.h"

#ifndef WIN32
int ovs_fchmod(int fd, const char *mode) OVS_WARN_UNUSED_RESULT;
int ovs_fchown(int fd, const char *usrstr) OVS_WARN_UNUSED_RESULT;

int ovs_kchmod(const char *path, const char *mode) OVS_WARN_UNUSED_RESULT;
int ovs_kchown(const char *path, const char *usrstr) OVS_WARN_UNUSED_RESULT;

int ovs_strtousr(const char *user_spec, uid_t *uid, char **user,
                 gid_t *gid, bool validate_user_group) OVS_WARN_UNUSED_RESULT;
#endif

#endif
