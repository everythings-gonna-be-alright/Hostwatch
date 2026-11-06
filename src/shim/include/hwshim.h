#ifndef HWSHIM_H
#define HWSHIM_H
#include <sys/types.h>

/// shm_open is variadic, which Swift can't call: this passes the mode through a fixed signature.
int hw_shm_open(const char *name, int oflag, mode_t mode);
int hw_shm_unlink(const char *name);

#endif
