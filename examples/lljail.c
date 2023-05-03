#define _GNU_SOURCE
#define LLUNVEIL_USE_UNVEIL
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <llunveil.h>

static void help() {
    puts("  lljail [-[rwxc] PATH] -- [ARGV]");
    puts("Restricts file access of a launched executabled");
    puts("");
    puts("Options:");
    puts("  -r PATH permit only reading for the path");
    puts("  -w PATH permit only writing for the path");
    puts("  -x PATH permit only execute for the path");
    puts("  -c PATH permit only create  for the path");
    puts("  You an also compose these options.");
    puts("");
    puts("  -h | --help show this help message");
    puts("");
    puts("Example:");
    puts("  lljail -r /bin -rw /tmp -rw /dev -r /etc -- /bin/bash");
}

static _Bool is_flag_valid(const char* flag)
{
    if(strlen(flag) < 2)
        return 0;
    if(flag[0] != '-')
        return 0;

    for(size_t i=1;flag[i] != '\0';i++) {
        const char* acceptable = "rwxc";
        if(strchr(acceptable, flag[i]) == NULL)
            return 0;
    }
    return 1;
}

int main(int argc, char *argv[], char **envp) {
    if(argc == 1) {
        help();
        return 1;
    }

    char* flag = NULL;
    char* path = NULL;
    int i;
    for(i=1;i<argc;i++) {
        char* arg = argv[i];
        if(strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            help();
            return 0;
        }
        else if(strcmp(arg, "--") == 0) {
            break;
        }
        
        if(i%2 == 1) {
            if(is_flag_valid(arg) == 0) {
                fprintf(stderr, "Unrecognized flag %s. A flag must be composed from the set [rwxc]\n", arg);
                return 1;
            }
            flag = (arg+1);
        }
        else {
            path = arg;
            // Add new path into our ruleset
            if(unveil(path, flag) != 0) {
                fprintf(stderr, "unveil() failed. Error: %s\n", strerror(errno));
            }
        }
    }
    // Unlike OpenBSD unveil. llunveil enables protection on unveil(NULL, NULL) (locking down)
    if(unveil(NULL, NULL) != 0) {
        fprintf(stderr, "failed to lockdown landock ruleset. %s", strerror(errno));
    }

    if(strcmp(argv[i], "--") != 0 || i+1 == argc) {
        fprintf(stderr, "Missing program to execute\n");
        return 1;
    }
    i++;


    char *cmd_path = argv[i];
    char **cmd_argv = argv+i;
    execvpe(cmd_path, cmd_argv, envp);
    // This block of code should now be executed if execvpe() is running correctly. No need to explicit check
    fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
            strerror(errno));
    fprintf(stderr, "Hint: access to the binary, the interpreter or "
            "shared libraries may be denied.\n");
    return 1;
}

