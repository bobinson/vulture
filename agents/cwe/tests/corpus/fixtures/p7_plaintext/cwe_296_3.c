#include <openssl/x509_vfy.h>

void configure(X509_STORE_CTX *store_ctx) {
  X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(store_ctx);
  X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
}
