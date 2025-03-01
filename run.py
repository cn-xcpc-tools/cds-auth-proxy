#!/usr/bin/env python3

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path


def print_banner():
    print("""\
+------------------------------------------------+
| Contest Data Server Media Authentication Proxy |
| Version 0.1.0                                  |
| Licensed under the MIT License                 |
+------------------------------------------------+
""")


def generate_certificate():
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    if (certs_dir / "").exists():
        print("key.pem already exists, skipping certificate generation.")
        print()
        return

    print("Generating self-signed certificate...")
    print("For production use, please use a valid certificate.")
    print()

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # Generate EC private key using NIST P-256 curve (prime256v1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate certificate
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    # Write certificate and private key to certs directory
    (certs_dir / "key.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (certs_dir / "key.pem").chmod(0o600)
    (certs_dir / "cert.pem").write_bytes(cert.public_bytes(encoding=serialization.Encoding.PEM))


def run_server():
    import logging

    from hypercorn.config import Config
    from hypercorn.run import run

    config = Config()
    config.bind = "0.0.0.0:5283"
    config.keyfile = Path("certs") / "key.pem"
    config.certfile = Path("certs") / "cert.pem"
    config.application_path = "app:app"
    config.accesslog = logging.getLogger("hypercorn.access")
    config.errorlog = logging.getLogger("hypercorn.error")

    run(config)


def main():
    # Change to script's directory
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)

    print_banner()
    generate_certificate()
    run_server()


if __name__ == "__main__":
    main()
