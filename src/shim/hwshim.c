#include "hwshim.h"
#include <sys/mman.h>

int hw_shm_open(const char *name, int oflag, mode_t mode) { return shm_open(name, oflag, mode); }
int hw_shm_unlink(const char *name) { return shm_unlink(name); }
