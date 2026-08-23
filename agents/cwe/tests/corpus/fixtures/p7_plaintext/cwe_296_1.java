package com.example.transport;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public final class GatewayTrust implements X509TrustManager {

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType) {
    delegate.checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType) {}

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return delegate.getAcceptedIssuers();
  }
}
