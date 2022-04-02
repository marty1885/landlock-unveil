#ifndef LLUNVEIL_H
#define LLUNVEIL_H

#ifdef __cplusplus
extern "C" {
#endif

int llunveil(const char *path, const char *permissions);

#ifdef __cplusplus
}
#endif

#ifdef LLUNVEIL_USE_UNVEIL
#define unveil(path, permissions) llunveil(path, permissions)
#endif

#endif
