from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import os

def generate_ssl_certs(output_dir: str = "certs"):
    """Generate self-signed SSL certificates for development"""
    try:
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate public key
        public_key = private_key.public_key()
        
        # Create self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DCM Development"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        ).sign(private_key, hashes.SHA256())
        
        # Write private key
        with open(os.path.join(output_dir, "key.pem"), "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Write certificate
        with open(os.path.join(output_dir, "cert.pem"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        print("SSL certificates generated successfully!")
        
    except Exception as e:
        print(f"Error generating SSL certificates: {str(e)}")
        raise

if __name__ == "__main__":
    generate_ssl_certs() 