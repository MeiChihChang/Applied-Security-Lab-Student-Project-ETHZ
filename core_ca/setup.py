import os
import datetime
from OpenSSL import crypto

##############################################
DIR = os.path.join(os.curdir, 'certs')
VERSION = 2
# Root CA
ROOT_PK = 'root_pk.pem'
ROOT_CERT = 'root_cert.pem'
ROOT_CERT2 = 'root_cert.txt'
ROOT_CRL = 'root_crl.pem'
# Intermediate CA (ICA)
CRL_FILE = 'crl.txt'
SRNR_FILE = 'srlnr.txt'
CERT_FILE = 'imovies_cert.pem'
CERT_FILE2 = 'imovies_cert.txt'
PK_FILE = 'imovies_pk.pem' 
# Intermediate CA (ICA) internal network
NET_DIR = os.path.join(os.pardir, 'keys_and_certificates')
NET_CERT_FILE = 'network_ca_cert.pem'
NET_PK_FILE = 'network_ca_pk.pem'
CERTHOST_CERT = 'certhost_cert.pem'
CERTHOST_PK = 'certhost_pk.pem'
WEBSERV_CERT = 'webserver_cert.pem'
WEBSERV_PK = 'webserver_pk.pem'
##############################################


##############################################
# Create Root CA and ICA for client certs
##############################################
def get_asn1_time(offset = datetime.timedelta(days=0)):
  time = datetime.datetime.now()
  time += offset
  time -= datetime.timedelta(hours=1)
  res = time.strftime('%Y%m%d%H%M%S') + 'Z'
  return res.encode('utf-8')

# Get timestamps
t_now = get_asn1_time()
t_after = get_asn1_time(datetime.timedelta(days=5*365))
t_update = get_asn1_time(datetime.timedelta(days=100))

if not os.path.exists(DIR):
    os.makedirs(DIR)

# Create Root pk and store it in main dir (s.t. it is kept offline)
root_k = crypto.PKey()
root_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, ROOT_PK)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, root_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

# Create self-signed root certificate
root_cert = crypto.X509()
root_cert.set_version(VERSION)
root_cert.get_subject().CN = "root@imovies.ch"
root_cert.get_subject().O = "iMovies AG"
root_cert.set_serial_number(0)
root_cert.set_notBefore(t_now)
root_cert.set_notAfter(t_after)
root_cert.set_issuer(root_cert.get_subject())
root_cert.set_pubkey(root_k)
root_cert.add_extensions([
  crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
  crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
  crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=root_cert),
])
root_cert.sign(root_k, 'sha256')

filename = os.path.join(NET_DIR, ROOT_CERT)
root_c = crypto.dump_certificate(crypto.FILETYPE_PEM, root_cert).decode("utf-8")
f = open(filename, "wt").write(root_c)
filename = os.path.join(DIR, ROOT_CERT)
f = open(filename, "wt").write(root_c)
filename = os.path.join(NET_DIR, ROOT_CERT2)
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, root_cert).decode("utf-8")
f = open(filename, "wt").write(c)

# Create Root CRL
t_now = get_asn1_time()
t_update = get_asn1_time(datetime.timedelta(days=100))
crl = crypto.CRL()
crl.set_lastUpdate(t_now)
crl.set_nextUpdate(t_update)
crl.set_version(1)
crl.sign(root_cert, root_k, b'sha256')

filename = os.path.join(DIR, ROOT_CRL)
c = crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode("utf-8")
f = open(filename, "wt").write(c)
filename = os.path.join(DIR, 'root_crl.txt')
c = crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode("utf-8")
f = open(filename, "wt").write(c)

# Create ICA pk
imovies_k = crypto.PKey()
imovies_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(DIR, PK_FILE)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, imovies_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

# Create iMovies ICA certificate issued by root
req = crypto.X509Req()
req.get_subject().CN = 'user_ca@imovies.ch'
req.get_subject().O = "iMovies AG"
req.get_subject().emailAddress = 'user_ca@imovies.ch'
req.set_pubkey(imovies_k)
req.sign(imovies_k, 'sha256')
cert = crypto.X509()
cert.set_version(VERSION)
cert.set_subject(req.get_subject())
cert.set_serial_number(1)
cert.set_notBefore(t_now)
cert.set_notAfter(t_after)
cert.set_issuer(root_cert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
cert.add_extensions([
  crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
  crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
  crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
])
cert.sign(root_k, 'sha256')

filename = os.path.join(DIR, CERT_FILE)
c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
f = open(filename, "wt").write(c)
filename = os.path.join(DIR, CERT_FILE2)
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode("utf-8")
f = open(filename, "wt").write(c)


##############################################
# Create ICA for host certs
##############################################

# Create a new ICA dedicated for ours servers in network
# Create ICA pk
net_ca_k = crypto.PKey()
net_ca_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, NET_PK_FILE)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, net_ca_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

# Create iMovies ICA certificate issued by root
req = crypto.X509Req()
req.get_subject().CN = 'network_ca@imovies.ch'
req.get_subject().O = "iMovies AG"
req.get_subject().emailAddress = 'network_ca@imovies.ch'
req.set_pubkey(net_ca_k)
req.sign(net_ca_k, 'sha256')
cert = crypto.X509()
cert.set_version(VERSION)
cert.set_subject(req.get_subject())
cert.set_serial_number(2)
cert.set_notBefore(t_now)
cert.set_notAfter(t_after)
cert.set_issuer(root_cert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
cert.add_extensions([
  crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
  crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
  crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
])
cert.sign(root_k, 'sha256')
net_ca_cert = cert

filename = os.path.join(NET_DIR, NET_CERT_FILE)
net_c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
f = open(filename, "wt").write(net_c)
filename = os.path.join(NET_DIR, 'network_ca_cert.txt')
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode("utf-8")
f = open(filename, "wt").write(c)

# Create user keypair
host_k = crypto.PKey()
host_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, CERTHOST_PK)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, host_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

# Create Host Certificate
# Create Certificate Signing Request (CSR)
req = crypto.X509Req()
req.get_subject().CN = '192.168.33.15'
req.get_subject().O = 'Imovies AG'
req.get_subject().emailAddress = 'certhost@imovies.ch'
req.set_pubkey(host_k)
req.sign(host_k, 'sha256')
# Create Certificate from CS        
t_now = get_asn1_time()
t_after = get_asn1_time(datetime.timedelta(days=5*365))
cert = crypto.X509()
cert.set_version(VERSION)
cert.set_subject(req.get_subject())
cert.set_serial_number(0)
cert.set_notBefore(t_now)
cert.set_notAfter(t_after)
cert.set_issuer(net_ca_cert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
domain_list = ["IP:192.168.33.15", "IP:127.0.0.1"]
cert.add_extensions([
    crypto.X509Extension(
        b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
    crypto.X509Extension(
        b'subjectAltName', False, (', '.join(domain_list)).encode()
   )
])
cert.sign(net_ca_k, 'sha256')

# Save Certificate and archive Key in user dir
filename = os.path.join(NET_DIR, CERTHOST_CERT)
c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8") + net_c
f = open(filename, "wt").write(c)
filename = os.path.join(NET_DIR, 'certhost_cert.txt')
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode("utf-8")
f = open(filename, "wt").write(c)

# Create user keypair
host_k = crypto.PKey()
host_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, WEBSERV_PK)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, host_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

# Create Host Certificate
# Create Certificate Signing Request (CSR)
req = crypto.X509Req()
req.get_subject().CN = '192.167.33.81'
req.get_subject().O = 'Imovies AG'
req.get_subject().emailAddress = 'webserver@imovies.ch'
req.set_pubkey(host_k)
req.sign(host_k, 'sha256')
# Create Certificate from CS        
t_now = get_asn1_time()
t_after = get_asn1_time(datetime.timedelta(days=5*365))
cert = crypto.X509()
cert.set_version(VERSION)
cert.set_subject(req.get_subject())
cert.set_serial_number(1)
cert.set_notBefore(t_now)
cert.set_notAfter(t_after)
cert.set_issuer(net_ca_cert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
domain_list = ["IP:192.167.33.81", "IP:192.168.33.35", "IP:127.0.0.1"]
cert.add_extensions([
    crypto.X509Extension(
        b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
    crypto.X509Extension(
        b'subjectAltName', False, (', '.join(domain_list)).encode()
   )
])


cert.sign(net_ca_k, 'sha256')

# Save Certificate and archive Key in user dir
filename = os.path.join(NET_DIR, WEBSERV_CERT)
c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8") + net_c
f = open(filename, "wt").write(c)
filename = os.path.join(NET_DIR, 'webserver_cert.txt')
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode("utf-8")
f = open(filename, "wt").write(c)
