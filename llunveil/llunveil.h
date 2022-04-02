#ifndef LLUNVEIL_H
#define LLUNVEIL_H

int llunveil(const char *path, const char *permissions);

#ifdef LLUNVEIL_USE_UNVEIL
#define unveil(path, permissions) llunveil(path, permissions)
#endif

#endif
