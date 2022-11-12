#ifndef __CBMEM_WINDOWS_H
#define __CBMEM_WINDOWS_H

#include <stdint.h>

int driver_init(void);
int driver_deinit(void);
uint8_t *driver_phys_read(unsigned long long phys, size_t sz);

#endif
