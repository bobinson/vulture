package com.example.transport;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;

public final class ClientFactory {

  public static HttpClientBuilder builder() {
    HttpClientBuilder builder = HttpClientBuilder.create();
    builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
    return builder;
  }
}
