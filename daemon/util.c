/**
 * Copyright 2018-2021 Shawn Anastasio
 *
 * This file is part of libkvmchan.
 *
 * libkvmchan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libkvmchan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libkvmchan.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>

#ifdef USE_PRIVSEP
#include <pwd.h>
#include <grp.h>
#endif

#include "util.h"

long SYSTEM_PAGE_SIZE;

__attribute__((constructor))
void initialize_util(void) {
    SYSTEM_PAGE_SIZE = sysconf(_SC_PAGESIZE);
    ASSERT(SYSTEM_PAGE_SIZE);
}

#define vec_template(Tname, T) \
bool vec_ ## Tname ## _init(struct vec_ ## Tname *v, size_t initial_size, void (*destructor)(T)) { \
    if (initial_size < 10) \
        initial_size = 10; \
\
    v->data = calloc(initial_size, sizeof(T)); \
    if (!(v->data)) \
        return false; \
\
    v->size = initial_size; \
    v->count = 0; \
    v->destructor = destructor; \
    return true; \
}; \
\
bool vec_ ## Tname ## _push_back(struct vec_ ## Tname *v, T element) { \
    if (v->size == v->count) { \
        /* double array size */ \
        size_t new_size = v->size * 2; \
        void *new_data = reallocarray(v->data, new_size, sizeof(T)); \
        if (!new_data) \
            return false; \
        v->data = new_data; \
        v->size = new_size; \
    } \
    /* insert element into array */ \
    v->data[v->count++] = element; \
    return true; \
} \
\
T vec_ ## Tname ## _at(struct vec_ ## Tname *v, size_t i) { \
    assert(i < v->count); \
    return v->data[i]; \
} \
\
void vec_ ## Tname ## _remove(struct vec_ ## Tname *v, size_t i) { \
    assert(i < v->count); \
\
    if (v->destructor) \
        v->destructor(v->data[i]); \
\
    if (i != (v->count - 1)) \
        memmove(v->data + i, v->data + i + 1, sizeof(T) * (v->count - i - 1)); \
    v->count -= 1; \
} \
void vec_ ## Tname ## _destroy(struct vec_ ## Tname *v) { \
    size_t s = v->count; \
    while (s-- > 0) { \
        vec_ ## Tname ## _remove(v, s); \
    } \
    free(v->data); \
} \
bool vec_ ## Tname ## _contains(struct vec_ ## Tname *v, T element, Tname ## _comparator comparator) { \
    for (size_t i=0; i<v->count; i++) { \
        if (comparator && !comparator(v->data[i], element)) \
            return true; \
        else if (!comparator && (v->data[i] == element)) \
            return true; \
    } \
    return false; \
}

vec_template(voidp, void*)
vec_template(int, int)
vec_template(u32, uint32_t)

struct llist_footer *llist_generic_get_footer(struct llist_generic *l, void *ptr) {
    return (struct llist_footer *)((char *)ptr + l->element_size);
}

struct llist_footer *llist_generic_get_footer_unsafe(void *ptr, size_t element_size) {
    return (struct llist_footer *)((char *)ptr + element_size);
}

#ifdef UTIL_NO_ASSERT_ON_FAILURE
#define ASSERT_OPTIONAL(x) (void)0
#define ASSERT_OR_RETURN_NULL(x) do if (!(x)) return NULL; while (0)
#else
#define ASSERT_OPTIONAL(x) ASSERT(x)
#define ASSERT_OR_RETURN_NULL(x) ASSERT(x)
#endif

void llist_generic_init(struct llist_generic *l, size_t element_size, void (*destructor)(void *), void *user) {
    l->first = NULL;
    l->last = NULL;
    l->element_size = element_size;
    l->count = 0;
    l->destructor = destructor;
    l->user = user;
}

void *llist_generic_new_at_front(struct llist_generic *l) {
    void *new_block = calloc(1, l->element_size + sizeof(struct llist_footer));
    ASSERT_OR_RETURN_NULL(new_block);
    struct llist_footer *footer = llist_generic_get_footer(l, new_block);
    footer->prev = NULL;
    footer->next = l->first;
    footer->parent_list = l;
    if (footer->next) {
        struct llist_footer *next_footer = llist_generic_get_footer(l, footer->next);
        ASSERT_OPTIONAL(!next_footer->prev);
        next_footer->prev = new_block;
    }
    l->first = new_block;
    l->count++;
    return new_block;
}

void *llist_generic_new_at_back(struct llist_generic *l) {
    void *new_block = calloc(1, l->element_size + sizeof(struct llist_footer));
    ASSERT_OR_RETURN_NULL(new_block);
    struct llist_footer *footer = llist_generic_get_footer(l, new_block);
    footer->prev = l->last;
    footer->next = NULL;
    footer->parent_list = l;
    if (footer->prev) {
        struct llist_footer *prev_footer = llist_generic_get_footer(l, footer->prev);
        ASSERT_OPTIONAL(!prev_footer->next);
        prev_footer->next = new_block;
    }
    l->last = new_block;
    l->count++;
    return new_block;
}

void *llist_generic_new_after(struct llist_generic *l, void *entry) {
    struct llist_footer *entry_footer = llist_generic_get_footer(l, entry);
    ASSERT_OR_RETURN_NULL(entry_footer->parent_list == l);

    void *new_block = calloc(1, l->element_size + sizeof(struct llist_footer));
    ASSERT_OR_RETURN_NULL(new_block);
    struct llist_footer *new_footer = llist_generic_get_footer(l, new_block);

    new_footer->next = entry_footer->next;
    new_footer->prev = entry;
    new_footer->parent_list = l;
    entry_footer->next = new_block;
    if (new_footer->next) {
        struct llist_footer *next_footer = llist_generic_get_footer(l, new_footer->next);
        next_footer->prev = new_block;
    }
    l->count++;
    return new_block;
}

void llist_generic_remove(struct llist_generic *l, void *entry) {
    struct llist_footer *footer = llist_generic_get_footer(l, entry);
    ASSERT_OPTIONAL(footer->parent_list == l);

    // Call user-provided destructor
    if (l->destructor)
        l->destructor(entry);

    // Remove entry from list
    if (footer->prev) {
        struct llist_footer *prev_footer = llist_generic_get_footer(l, footer->prev);
        prev_footer->next = footer->next;
    }
    if (footer->next) {
        struct llist_footer *next_footer = llist_generic_get_footer(l, footer->next);
        next_footer->prev = footer->prev;
    }

    // Update first/last references in main struct if necessary
    if (l->first == entry)
        l->first = footer->next;
    if (l->last == entry)
        l->last = footer->prev;

    l->count--;
    free(entry);
}

void llist_generic_destroy(struct llist_generic *l) {
    // Walk the list and destroy all entries
    void *cur = l->first;
    while (cur) {
        struct llist_footer *footer = llist_generic_get_footer(l, cur);
        void *next = footer->next;

        llist_generic_remove(l, cur);

        cur = next;
    }
}

void free_destructor(void *element) {
    free(element);
}

// Determines if a given string is purely numerical ('0'-'9')
bool str_is_number(const char *str) {
    char c;
    while((c = *str++))
        if (!isdigit(c))
            return false;

    return true;
}

const char *log_level_names[] = {
    "[INFO]",
    "[WARN]",
    "[ERROR]",
    "[BUG]"
};

void log_impl(enum log_level level, const char *file, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "%s %s:%d: ", log_level_names[level], file, line);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);

    va_end(args);
}

int add_epoll_fd(int epoll_fd, int fd, int event) {
    struct epoll_event ep_event = {
        .events = event,
        .data = {
            .fd = fd
        }
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ep_event);
}

int del_epoll_fd(int epoll_fd, int fd) {
    struct epoll_event ep_event = {
        .data = {
            .fd = fd
        }
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ep_event);
}


// A callback to be executed at program exit
struct exit_callback {
    void (*func)(void *);
    void *arg;
};

static struct vec_voidp callbacks;

bool install_exit_callback(void (*func)(void*), void *arg) {
    static bool init_done = false;
    if (!init_done) {
        if (!vec_voidp_init(&callbacks, 5, NULL))
            return false;

        init_done = true;
    }

    struct exit_callback *cb = malloc_w(sizeof(struct exit_callback));
    if (!cb)
        return false;
    cb->func = func;
    cb->arg = arg;

    vec_voidp_push_back(&callbacks, cb);
    return true;
}

void run_exit_callbacks(void) {
    for(size_t i=0; i<callbacks.count; i++) {
        struct exit_callback *cb = callbacks.data[i];
        cb->func(cb->arg);
    }
}

__attribute__((noreturn)) void bail_out(void) {
    // TODO: Check if in parent or child process
    run_exit_callbacks();
    _exit(EXIT_FAILURE);
}

ssize_t socmsg_send(int socfd, void *data, size_t len, int fd) {
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;

    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = data, .iov_len = len };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = (fd > 0) ? u.cmsgbuf : NULL,
        .msg_controllen = (fd > 0) ? CMSG_LEN(sizeof(int)) : 0,
    };

    /* Initialize the control message to hand off the fd */
    if (fd > 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(cmsg) = fd;
    }

    return sendmsg(socfd, &msg, 0);
}

ssize_t socmsg_recv(int socfd, void *buf, size_t len, int *fd_out) {
    ssize_t s;
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;

    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = u.cmsgbuf,
        .msg_controllen = CMSG_LEN(sizeof(int))
    };

    if ((s = recvmsg(socfd, &msg, 0)) < 0)
        return s;

    if (fd_out) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (msg.msg_controllen != CMSG_LEN(sizeof(int))) {
            *fd_out = -1;
            goto out;
        }

        *fd_out = *((int *)CMSG_DATA(cmsg));
    }

out:
    return s;
}

int eventfd_sem_init(uint64_t initial_value) {
    return eventfd(initial_value, EFD_SEMAPHORE | EFD_NONBLOCK);
}

void eventfd_sem_post(int evfd) {
    uint64_t buf = 1;
    ASSERT(write(evfd, &buf, sizeof(buf)) >= 0);
}

void eventfd_sem_wait(int evfd) {
    uint64_t buf;
    fd_set rfds;
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(evfd, &rfds);
        ASSERT(select(evfd + 1, &rfds, NULL, NULL, NULL) >= 0);

        if (FD_ISSET(evfd, &rfds)) {
            // The eventfd was ready for read, though it is possible
            // that in the time since select(2)'s return someone else acquired
            // the lock, so we have to be prepared to loop again in case of failure.
            if (read(evfd, &buf, sizeof(buf)) >= 0)
                break; // Success
        }
    }
}

/**
 * Wait for a semaphore eventfd to become readable OR for another fd to become readable.
 *
 * @return whether the eventfd was the one that became readable
 */
bool eventfd_sem_wait_or(int evfd, int other) {
    uint64_t buf;
    fd_set rfds;
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(evfd, &rfds);
        FD_SET(other, &rfds);
        ASSERT(select(MAX(evfd, other) + 1, &rfds, NULL, NULL, NULL) >= 0);

        if (FD_ISSET(evfd, &rfds)) {
            // The eventfd was ready for read, though it is possible
            // that in the time since select(2)'s return someone else acquired
            // the lock, so we have to be prepared to loop again in case of failure.
            if (read(evfd, &buf, sizeof(buf)) >= 0)
                return true;
        } else if (FD_ISSET(other, &rfds)) {
            // `other` is ready for read - return early
            return false;
        }
    }
}

#ifdef USE_PRIVSEP
uid_t get_uid_for_username(const char *username) {
    uid_t ret = (uid_t)-1;

    long getpw_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (getpw_max == -1)
        goto out;

    struct passwd passwd_storage;
    char *passwd_buf = malloc_w(getpw_max);
    struct passwd *result;
    int res = getpwnam_r(username, &passwd_storage, passwd_buf, getpw_max, &result);
    if (res != 0 || !result) {
        log(LOGL_ERROR, "Failed to lookup UID for username %s", username);
        goto out_malloc;
    }

    ret = result->pw_uid;

out_malloc:
    free(passwd_buf);
out:
    return ret;
}

gid_t get_gid_for_groupname(const char *groupname) {
    gid_t ret = (gid_t)-1;

    long getgr_max = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (getgr_max == -1)
        goto out;

    struct group group_storage;
    char *group_buf = malloc_w(getgr_max);
    struct group *result;
    int res = getgrnam_r(groupname, &group_storage, group_buf, getgr_max, &result);
    if (res != 0 || !result) {
        log(LOGL_ERROR, "Failed to lookup GID for groupname %s", groupname);
        goto out_malloc;
    }

    ret = result->gr_gid;

out_malloc:
    free(group_buf);
out:
    return ret;
}
#endif

bool drop_privileges(bool child) {
#ifdef USE_PRIVSEP

#if !defined(PRIVSEP_USER) || !defined(PRIVSEP_GROUP)
#error "Built with USE_PRIVSEP but no PRIVSEP_USER/PRIVSEP_GROUP was defined!"
#endif

    gid_t target_gid = get_gid_for_groupname(PRIVSEP_GROUP);
    if (target_gid == (gid_t)-1)
        return false;

    uid_t target_uid = get_uid_for_username(PRIVSEP_USER);
    if (target_uid == (uid_t)-1)
        return false;

    if (setgid(target_gid) != 0) {
        log(LOGL_ERROR, "setgid() failed: %m");
        return false;
    }

    if (setuid(target_uid) != 0) {
        log(LOGL_ERROR, "setuid() failed: %m");
        return false;
    }

    if (child) {
        // setuid() causes PR_SET_PDEATHSIG to be reset, so we have to do it again after dropping privileges.
        // https://stackoverflow.com/questions/45139073/detect-death-of-parent-process-from-setuid-process
        prctl_w(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0);
    }

    return true;
#else

#ifndef KVMCHAN_LIBRARY
#warning "Building without privilege separation - kvmchand will run as root at all times!"
#endif

    (void)child;
    return true;
#endif
}
