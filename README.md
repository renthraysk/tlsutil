# tlsutil

Example of creating a tls.Config

```
    cfg, err := NewTLSConfig(WithTLS12(),
        WithKeyPair("localhost.pem", "localhost.key"))
