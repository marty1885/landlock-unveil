# llunveil

OpenBSD [unveil(2)][unveil] like function on Linux using [Landlock][landlock] (starting from Linux >= 5.13). Rewritten largely based on [gonack's landlockjail][landlockjail]

**Impoerant:** This is experimental software. DO NOT depend on it for security.

## Documentation

See OpenBSD unveil(2) for details. Like unveil(2), llunveil(2) allows a process to submit a set of paths and permissions that it is allowed to access, then deny access to all files and directories that it didn't submit later. The API of `llunveil` is like `unveil`. But with a major difference.

* Filesystem protection is activated upon calling `unveil(NULL, NULL)`

Instead of activating upon calling the unveil function. Protections have to be commited in llunveil for it to take effect. For example:

```c
#define LLUNVEIL_USE_UNVEIL // create a macro called `unveil`. Prevent conflict
#include <llunveil.h>
...

unveil("/home/user/", "r");
// Not activated until calling unveil(NULL, NULL);
assert(fopen("/tmp/some_text.txt", "r") != NULL);

unveil(NULL, NULL); // activate!
assert(fopen("/tmp/some_text.txt", "r") == NULL);
```

[unveil]: https://man.openbsd.org/unveil
[landlock]: https://landlock.io/
[landlockjail]: https://github.com/gnoack/landlockjail

## How to build

You need a C11 compatiable compiler. And be on Linux >= 5.13 (for the syscall numbers). And CMake for build generation.

```
mkdir build
cmake ..
make -j
```

### Example program

`lljail` is a completely rewritten application based on `landlockjail` that launches a program with restricted file access.

```
marty@zack ~/D/l/build> ./lljail -r /usr -rx /usr/lib -rx /usr/lib64 -rx /lib64 -rx /bin -r /tmp -- /bin/bash
bash: /etc/bash.bashrc: Permission denied
bash: /home/marty/.bashrc: Permission denied
bash-5.1$ # We see permission denied because we didn't allow access to /etc and ~ in lljail
bash-5.1$ # Likewise we can't write to /tmp
bash-5.1$ echo Hello World > /tmp/asd
bash: /tmp/asd: Permission denied
bash-5.1$ exit
marty@zack ~/D/l/build> ./lljail -r /usr -rx /usr/lib -rx /usr/lib64 -rx /lib64 -rx /bin -rwc /tmp -r /etc -r $HOME -rw /dev -- /bin/bash
[marty@zack build]$ # Now BASH has full access to the folders. And we gave _write_ and _create_ permission to /tmp.
[marty@zack build]$ echo Hello World > /tmp/asd # Now this works
[marty@zack build]$ cat /tmp/asd
Hello World
[marty@zack build]$ # But we still can't execute anything in /usr/local/bin
[marty@zack build]$ /usr/local/bin/example
bash: /usr/local/bin/example: Permission denied
```



## TODO

- [ ] Make unit tests
- [ ] Ensure same behaivour as OpenBSD's
- [ ] Remove debug error prints
- [ ] Proper `errno`