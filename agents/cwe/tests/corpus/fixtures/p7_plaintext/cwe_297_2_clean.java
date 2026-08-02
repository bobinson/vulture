package com.example.transport;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;

public final class ClientFactory {

  public static HttpClientBuilder builder() {
    HttpClientBuilder builder = HttpClientBuilder.create();
    builder.setSSLHostnameVerifier(new DefaultHostnameVerifier());
    return builder;
  }
}
