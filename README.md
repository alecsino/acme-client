# ACME Client

This project is a Python implementation of an ACME (Automated Certificate Management Environment) client. It interacts with an ACME server to automate the process of obtaining and managing SSL/TLS certificates.

## Features

- DNS and HTTP challenge solving
- Certificate generation
- Certificate revocation

## Dependencies

This project uses the following Python libraries:

- `requests`
- `pycryptodome`
- `pyopenssl`
- `dnslib`

## Usage

To use this client, simply run the `client.py` script. The script will automatically handle the process of obtaining a certificate from an ACME server.

```bash
python client.py
```

## Configuration

The client can be configured through command line arguments. The available arguments are:

- `dir`: The directory of the ACME server.
- `dns_record`: The DNS record to use for DNS challenges.
- `domains`: The domains to obtain a certificate for.
- `challenge_type`: The type of ACME challenge to solve. Can be either `http01` for HTTP challenges or `dns01` for DNS challenges.
- `revoke`: Whether to revoke the certificate after obtaining it.

## Output

The obtained certificate is saved to `tmp/cert.pem`.

## Note

This is a basic implementation and may not include all features of the ACME protocol. It is intended for educational purposes and may not be suitable for production use.