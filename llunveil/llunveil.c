#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "llunveil.h"

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
    const struct landlock_ruleset_attr *const attr,
    const size_t size, const __u32 flags)
{
    // the syscall returns file descriptor and a file descriptor is always
    // integer on Linux. So, we can safely cast it to int.
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline long landlock_add_rule(const int ruleset_fd,
    const enum landlock_rule_type rule_type,
    const void *const rule_attr, const __u32 flags)
{
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
            rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline long landlock_restrict_self(const int ruleset_fd,
    const __u32 flags)
{
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

// HACK: Make llunveil compile on older kernels. The ABI should be stable so this is safe.
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#define ACCESS_FILE ( \
    LANDLOCK_ACCESS_FS_EXECUTE | \
    LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_READ_FILE | \
    LANDLOCK_ACCESS_FS_REFER)

#define ACCESS_FS_EXECUTE LANDLOCK_ACCESS_FS_EXECUTE

#define ACCESS_FS_READ (     \
    LANDLOCK_ACCESS_FS_READ_FILE | \
    LANDLOCK_ACCESS_FS_READ_DIR | \
    LANDLOCK_ACCESS_FS_REFER)

#define ACCESS_FS_WRITE ( \
    LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_TRUNCATE | \
    LANDLOCK_ACCESS_FS_REFER)

#define ACCESS_FS_CREATE ( \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR | \
    LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_REG | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
    LANDLOCK_ACCESS_FS_MAKE_SYM | \
    LANDLOCK_ACCESS_FS_REFER)

int populate_ruleset(int ruleset_fd, const char *path, __u64 allowed_access) {
    if(path == NULL) {
        errno = EFAULT;
        return -1;
    }
    int fd = open(path, O_PATH | O_CLOEXEC);
    if(fd < 0) {
        // We rely on `open()` to provide to correct ERRNO
        return -1;
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) != 0) {
        close(fd);
        return -1;
    }
    if(!S_ISDIR(statbuf.st_mode)) {
        allowed_access &= ACCESS_FILE;
    }

    struct landlock_path_beneath_attr path_beneath = {
        .parent_fd = fd,
        .allowed_access = allowed_access,
    };

    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                          &path_beneath, 0)) {
        perror("failed to update ruleset");
        close(fd);
        // landlock syscall sets the errno
        return -1;
    }

    return 0;
}

static struct landlock_ruleset_attr ruleset_attr;
static int ruleset_fd = -1;
static _Bool initialized = 0;
static _Bool commited = 0;

static int llunveil_init()
{
    int abi_version = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    // minimal required version is 1, according to the docs
    if(abi_version <= 0) {
        switch (errno) {
        case ENOSYS:
            perror("Landlock is not supported by your kernel"); break;
        case EOPNOTSUPP:
            perror("Landlock is not enabled in your kernel"); break;
        default:
            perror("Unknown error"); break;
        }
        return -1;
    }

    ruleset_attr.handled_access_fs = ACCESS_FS_READ | ACCESS_FS_WRITE
       | ACCESS_FS_CREATE | ACCESS_FS_EXECUTE;
    // Limit the available ruleset attributes to the kernel's supported ones.
    if(abi_version < 3)
        ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    if(abi_version < 2)
        ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;

    ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("Failed to create landlock ruleset");
        return -1;
    }
  
    return 0;
}

static int llunveil_commit()
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Failed to restrict privileges");
        return -1;
    }
    if (landlock_restrict_self(ruleset_fd, 0)) {
        perror("Failed to enforce ruleset");
        return -1;
    }
    close(ruleset_fd);
    ruleset_fd = -1;
    return 0;
}

static int llunveil_add_rule(const char* path, uint64_t permissions)
{
    if (populate_ruleset(ruleset_fd, path, permissions & ruleset_attr.handled_access_fs)) {
        fprintf( stderr, "Could not populate ruleset for %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

int llunveil(const char* path, const char* permissions)
{
    if(initialized == 0) {
      // The proper errno is set by llunveil_init()
        if(llunveil_init() != 0)
            return -1;
        initialized = 1;
    }

    // EPERM if we already commited
    if(commited) {
        errno = EPERM;
        return -1;
    }

    // both NULL means commit
    if(path == NULL && permissions == NULL) {
        assert(commited == 0);
        int status = llunveil_commit();
        commited = (status == 0);
        return status;
    }

    // EFAULT if path or permissions is NULL (OpenBSD behavior)
    if(path == NULL || permissions == NULL) {
        errno = EFAULT;
        return -1;
    }

    uint64_t permission_flags = 0;
    for(size_t i=0;permissions[i] != '\0'; i++) {
        switch(permissions[i]) {
            case 'w':
                permission_flags |= ACCESS_FS_WRITE;
                break;
            case 'r':
                permission_flags |= ACCESS_FS_READ;
                break;
            case 'x':
                permission_flags |= ACCESS_FS_EXECUTE;
                break;
            case 'c':
                permission_flags |= ACCESS_FS_CREATE;
                break;
            default:
                errno = EINVAL;
                return -1;
        }
    }
    return llunveil_add_rule(path, permission_flags);
}
