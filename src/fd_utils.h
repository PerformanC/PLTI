#ifndef PLTI_FD_UTILS_H
#define PLTI_FD_UTILS_H

#include <stdbool.h>

bool fdutil_write_fd(int sock, int fd);

int fdutil_read_fd(int sock);

#endif /* PLTI_FD_UTILS_H */
