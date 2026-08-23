#include <stdlib.h>
#include <time.h>

void issue(char *token, int n) {
  srand(time(NULL));
  for (int i = 0; i < n; i++) {
    token[i] = 'a' + (rand() % 26);
  }
}
