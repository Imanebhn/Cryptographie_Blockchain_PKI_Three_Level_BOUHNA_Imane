from flask import Flask, render_template, request, flash
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'pki_secret_key'

# Dossiers et fichiers requis
CERT_FOLDER = 'certs'
REVOKED_CERTS = 'revoked.txt'

# Création des dossiers/fichiers si absents
os.makedirs(CERT_FOLDER, exist_ok=True)
if not os.path.exists(REVOKED_CERTS):
    open(REVOKED_CERTS, 'w').close()

def generate_certificate(name, role, code):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Morocco"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyPKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path = os.path.join(CERT_FOLDER, f"{code}_{role}.crt")
    key_path = os.path.join(CERT_FOLDER, f"{code}_{role}.key")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return cert_path

@app.route('/', methods=['GET', 'POST'])
def index():
    cert_content = None

    if request.method == 'POST':
        name = request.form.get('name')
        role = request.form.get('role')
        code = request.form.get('code')
        action = request.form.get('action')

        cert_path = os.path.join(CERT_FOLDER, f"{code}_{role}.crt")

        if action == 'generate':
            generate_certificate(name, role, code)
            flash('Certificat généré avec succès.', 'success')

        elif action == 'display':
            if os.path.exists(cert_path):
                with open(cert_path, 'r') as f:
                    cert_content = f.read()
            else:
                flash('Certificat non trouvé.', 'error')

        elif action == 'revoke':
            if os.path.exists(cert_path):
                with open(REVOKED_CERTS, 'a') as f:
                    f.write(f"{code}_{role}.crt\n")
                os.remove(cert_path)
                flash('Certificat révoqué.', 'warning')
            else:
                flash('Certificat introuvable.', 'error')

    return render_template('index.html', cert=cert_content)

if __name__ == '__main__':
    app.run(debug=True)
