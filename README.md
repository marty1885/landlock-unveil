# llunveil

OpenBSD [unveil(2)][unveil] like function on Linux using [Landlock][landlock] (starting from Linux >= 5.13). Rewritten largely based on [gonack's landlockjail][landlockjail]

## Documentation

See OpenBSD [unveil(2)][unveil] documentation for details. Like unveil(2), llunveil allows a process to submit a set of paths and permissions that it is allowed to access, then deny access to all files and directories that it didn't submit later.

The API is simple. `unveil` is a function that takes two arguments: a path and a permission string. The permission string is a set of characters that represent the allowed operations on the path. The following characters are allowed:

* `r` - Makes the path available for read operations
* `w` - Makes the path available for write operations
* `x` - Makes the path available for execute operations
* `c` - Allows creation or deletion at or under the path

Then, to activate the restrictions, call `unveil(NULL, NULL)`. After that, the process will only be able to access the paths that were unveiled.

The API of `llunveil` is like `unveil`. But with a few differences:

* Filesystem protection is activated and committed upon calling `unveil(NULL, NULL)`
* Non-existing files cannot be unveiled. This is a limitation of Landlock.

Instead of activating upon calling the unveil function. Protections have to be commited in llunveil for them to take effect. For example:

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

You need a C11 compatible compiler. And be on Linux >= 5.13 (for the syscall numbers). And CMake for build generation.

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

## Example

The following example shows how to use `llunveil` to restrict access to a directory and its subdirectories. The program will be able to read files in `/home/user/` but not write to them. Also no error checking to keep it short.

```c
// create a macro called `unveil`. Prevent conflict
#define LLUNVEIL_USE_UNVEIL
#include <llunveil.h>
#include <stdio.h>

int main() {
    // Allow read access to /home/user/ and its subdirectories
    unveil("/home/user/", "r");
    unveil(NULL, NULL);

    // Since read access is allowed, opening a file for reading works
    FILE* file = fopen("/home/user/some_text.txt", "r");
    assert(file != NULL);
    char buffer[100];
    fgets(buffer, 100, file);

    // But writing to the file is not allowed
    FILE* file2 = fopen("/home/user/other_text.txt", "w");
    assert(file2 == NULL);
    return 0;
}
```


## TODO

- [ ] Make unit tests
- [x] Ensure behaviour close to OpenBSD's
- [x] Proper `errno`
