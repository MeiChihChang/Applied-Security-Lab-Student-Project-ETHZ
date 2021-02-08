#!flask/bin/python
import os
import base64
from flask import Flask, request, make_response, abort, jsonify, send_file
from cert_auth import CertificateAuthority

app = Flask(__name__)

CERT_DIR = os.path.join(os.path.curdir, 'certs')
imovies_ca = CertificateAuthority("iMovies CA", 'iMovies AG', CERT_DIR, 
    'root_cert.pem', 'root_crl.pem')


@app.route('/')
def index():
    return "This is the Web Interface for the Core CA"

@app.route('/new_cert', methods=['POST'])
def create_cert():
    if not request.json or not 'uid' in request.json:
        abort(400)
    r = request.json
    archive_bytes, crl = imovies_ca.issue_new_certificate(r['uid'], r['mail_addr'], r['passphrase'])
    pload = {'uid': r['uid'], 'archive': base64.b64encode(archive_bytes).decode('utf-8'), 'crl': crl}
    app.logger.info("Issued new certificate for " + r['uid'])
    return make_response(jsonify(pload), 200)

@app.route('/revoke_cert', methods=['POST'])
def revoke_cert():
    if not request.json or not 'uid' in request.json:
        abort(400)
    r = request.json
    status, crl = imovies_ca.revoke_certificate(r['uid'], None)
    pload = {'uid': r['uid'], 'status': status, 'crl': crl}
    app.logger.info("Request to revoke certificate for " + r['uid'] + ", status: " + status)
    return make_response(jsonify(pload), 200)

@app.route('/verify_cert', methods=['POST'])
def verify_cert():
    if not request.json or not 'certificate' in request.json:
        abort(400)
    r = request.json
    status = imovies_ca.verify_certificate(r['certificate'])
    pload = {'status': status}
    app.logger.info("Request to verify certificate, status: " + status)
    return make_response(jsonify(pload), 200)

@app.route('/ca_stats', methods=['GET'])
def get_ca_stats():
    pload = imovies_ca.get_ca_stats()
    app.logger.info("Request to ca stats")
    return jsonify(pload)

@app.errorhandler(404)
def not_found(error):
    app.logger.info("Received request to wrong resource!")
    return make_response(jsonify({'error': 'Not found!'}), 404)

@app.errorhandler(400)
def not_found(error):
    app.logger.info("Received malformed request!")
    return make_response(jsonify({'error': 'Request malformed!'}), 404)

if __name__ == '__main__':
    app.run(ssl_context=('certhost_cert.pem', 'certhost_pk.pem'), debug=True)