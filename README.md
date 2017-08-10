# tlsutil

Example of creating a tls.Config

```
    cfg := NewTLSConfig(WithTLS12(),
        WithKeyPair("localhost.pem", "localhost.key"))
