#include <stdio.h>

int apply(int mode, int fd) {
  int rc = 0;
  switch (mode) {
    case 1:
      rc = raise_privileges(fd);
      break;
    case 2:
      rc = drop_privileges(fd);
      break;
    default:
      rc = -1;
      break;
  }
  return rc;
}
