# Certificates

No certificate is included on purpose. Generate your own pair here; the files
are gitignored.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

Then start the server with both paths:

```bash
python run.py --port 8787 --tls-cert certs/server.crt --tls-key certs/server.key
```

The client has to trust that certificate: either import it on the device or
accept the warning once. Without `--tls-cert` the server speaks plain HTTP.
