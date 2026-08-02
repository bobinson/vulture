#include <stdlib.h>

void issue(char *token, int n, unsigned int entropy) {
  srand(entropy);
  for (int i = 0; i < n; i++) {
    token[i] = 'a' + (rand() % 26);
  }
}
