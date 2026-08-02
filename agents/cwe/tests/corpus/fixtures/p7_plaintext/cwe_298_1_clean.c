#include <openssl/x509_vfy.h>

void configure(X509_STORE *store) {
  X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
  X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
  X509_STORE_set1_param(store, param);
}
