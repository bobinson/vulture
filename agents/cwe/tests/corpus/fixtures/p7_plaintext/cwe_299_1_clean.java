package com.example.transport;

import java.security.cert.PKIXBuilderParameters;

public final class PkixSetup {

  public static void configure(PKIXBuilderParameters params) {
    params.setRevocationEnabled(true);
  }
}
