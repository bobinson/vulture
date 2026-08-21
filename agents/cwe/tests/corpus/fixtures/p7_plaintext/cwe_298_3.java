package com.example.transport;

import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

public final class PeerCheck {

  public boolean accept(X509Certificate cert) {
    try {
      cert.checkValidity();
    } catch (CertificateExpiredException e) {}
    return true;
  }
}
