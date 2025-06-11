from flask import Flask, render_template, request, redirect, flash
import subprocess
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_cert():
    cn = request.form['common_name']
    cert_type = request.form['cert_type']  # client or server
    folder = f"leaf-certs/{cert_type}/{cn}"
    os.makedirs(folder, exist_ok=True)

    key_path = os.path.join(folder, f"{cn}.key.pem")
    csr_path = os.path.join(folder, f"{cn}.csr.pem")
    cert_path = os.path.join(folder, f"{cn}.cert.pem")

    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"])
    subprocess.run(["openssl", "req", "-new", "-key", key_path, "-out", csr_path,
                    "-subj", f"/C=FR/ST=France/O=TestOrg/CN={cn}"])
    subprocess.run(["openssl", "ca", "-config", "intermediate-ca/openssl.cnf",
                    "-in", csr_path, "-out", cert_path,
                    "-batch", "-notext", "-days", "365", "-md", "sha256"])

    flash(f"Certificat pour {cn} généré avec succès.")
    return redirect('/')

@app.route('/revoke', methods=['POST'])
def revoke_cert():
    cn = request.form['common_name']
    cert_type = request.form['cert_type']
    cert_path = f"leaf-certs/{cert_type}/{cn}/{cn}.cert.pem"

    subprocess.run(["openssl", "ca", "-config", "intermediate-ca/openssl.cnf",
                    "-revoke", cert_path])
    subprocess.run(["openssl", "ca", "-gencrl", "-config", "intermediate-ca/openssl.cnf",
                    "-out", "intermediate-ca/crl/intermediate.crl.pem"])

    flash(f"Certificat pour {cn} révoqué.")
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
