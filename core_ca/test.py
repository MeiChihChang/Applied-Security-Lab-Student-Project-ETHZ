from cert_auth import CertificateAuthority
import os
import json
import base64
import datetime
import requests
from OpenSSL import crypto

# Use the root_cert.pem as trusted certificate to verify a https request.
TRUSTED_CERT = os.path.join(os.path.join(os.pardir, 'keys_and_certificates'), 'root_cert.pem')

# Create certificate for user with user id 'example'
# Current implementation supports 1 certificate per user
# if another one is issued previous is revoked and overridden
#
# Archive: PKCS12 archive encrypted with the passphrase holding the 
# ca trust chain, the user certificate, the user privatekey. It is 
# base64 encoded b.c. we cannot send bytearrays in a json object. 
# To get recreate the PKCS12 archive object from the base64 string use the
# code lines below.
#
# CRL: it also passes the updated certificate revocation list crl, this 
# is sent in case a certificate had to be revoke before we can issue a new
# one. B.C we only allow 1 certificate per user for simplicity of the ca 
# structure.
pload = {
        'uid':'example',
        'mail_addr': 'abc@student.ethz.ch',
        'passphrase':'123'
        }
r = requests.post('https://127.0.0.1:5000/new_cert', json = pload, verify=TRUSTED_CERT)
r = r.json()
print(r)
# Use the below code lines to recreate a PKCS archive object from 
# the response.
archive = base64.b64decode(r['archive'])
archive = crypto.load_pkcs12(archive, passphrase=b'123')
print(archive.get_privatekey())
print(archive)

'''
Response should look like this:
{
  "archive": "MIIQNQIBAzCCD/8GCSqGSIb3DQEHAaCC...",
  "crl": "-----BEGIN X509 CRL-----...",
  "uid": "example"
}
'''

# Revoke certificate for user with uid 'example'
# CRL: also here we pass the updated Certificate
# Revocation List crl 
pload = {
        'uid':'example',
        }
r = requests.post('https://127.0.0.1:5000/revoke_cert', json = pload, verify=TRUSTED_CERT)
print(r.json())

'''
Response should look like this:
{
  "crl": "-----BEGIN X509 CRL-----...",
  "status": "Revoked",
  "uid": "example"
}
'''

# verify certificate 
# send certificate in pem format! 
filename = os.path.join(os.curdir, os.path.join(os.path.join(os.path.join('certs'), 'example'), 'c.pem'))
cert = open(filename, 'rt').read()
pload = {
        'certificate': cert,
        }
r = requests.post('https://127.0.0.1:5000/verify_cert', json = pload, verify=TRUSTED_CERT)
print(r.json())

'''
Response should look like this:
{
  "status": "Invalid",
}
'''

# Get ca stats (Admin infos)
r = requests.get('https://127.0.0.1:5000/ca_stats', verify=TRUSTED_CERT)
print(r.json())

'''
Response should look like this, but values are probably different:
{
  "certificates": 9,
  "cur_serial_nr": 9,
  "revocations": 15
}
'''