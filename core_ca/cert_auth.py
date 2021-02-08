from OpenSSL import crypto
import os
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class CertificateAuthority:

    ##############################################
    CRL_FILE = 'crl.pem'
    SRNR_FILE = 'srlnr.txt'
    CERT_FILE = 'imovies_cert.pem'
    PK_FILE = 'imovies_pk.pem'
    VERSION = 2 
    USER_CERT = 'c.pem'
    USER_PK = 'encrypted_k.pem'
    USER_SK = 'encrypted_symmetric_k.pem'
    ##############################################

    def __init__(self, name, organization, cert_dir, root_certificate, root_crl):
        self.name = name
        self.cert_dir = cert_dir
        self.organization = organization
        
        # Load the CA dependent files
        self.root_certificate = self.load_certificate(cert_dir, root_certificate)
        self.root_public_key = self.root_certificate.get_pubkey()
        self.root_crl = self.load_crl(root_crl)
        self.private_key = self.load_private_key(self.cert_dir, self.PK_FILE)
        self.serial_nr = self.create_serial_nr()
        self.certificate = self.load_certificate(self.cert_dir, self.CERT_FILE)
        self.crl = self.create_crl()
        
    def issue_new_certificate(self, user_id, mail_addr, passphrase):
        # Revoke any existing certificate for user
        user_dir = os.path.join(self.cert_dir, user_id)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        elif os.path.exists(os.path.join(user_dir, self.CERT_FILE)):
            user_cert = self.load_certificate(user_dir, self.CERT_FILE)
            if (self.verify_certificate(user_cert) != 'Invalid'):
                self.revoke_certificate(user_id, None)

        # Create user keypair
        user_key = self.create_private_key()

        # Create Certificate Signing Request (CSR)
        req = crypto.X509Req()
        req.get_subject().CN = user_id
        req.get_subject().O = self.organization
        req.get_subject().emailAddress = mail_addr
        req.set_pubkey(user_key)
        req.sign(user_key, 'sha256')

        # Create Certificate from CSR
        t_now = self.get_asn1_time()
        t_after = self.get_asn1_time(datetime.timedelta(days=5*365))
        cert = crypto.X509()
        cert.set_version(self.VERSION)
        cert.set_subject(req.get_subject())
        cert.set_serial_number(self.serial_nr)
        self.serial_nr += 1
        self.write_serial_nr(self.serial_nr)
        cert.set_notBefore(t_now)
        cert.set_notAfter(t_after)
        cert.set_issuer(self.certificate.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(self.private_key, 'sha256')
        
        # Save Certificate and archive Key in user dir
        self.write_certificate(user_dir, self.USER_CERT, cert)
        self.archive_private_key(user_dir, user_key) 
        

        # Create PKCS#12 archive with ca certificate chain, users certificate and private key to return to user
        archive = crypto.PKCS12()
        archive.set_ca_certificates([self.root_certificate, self.certificate])
        archive.set_certificate(cert)
        archive.set_privatekey(user_key)
        archive_bytes = archive.export(passphrase=passphrase.encode())
        return archive_bytes, self.get_crl_as_pem_str(self.crl)
    
    def revoke_certificate(self, user_id, reason):
        # Check if revocation request is valid
        user_dir = os.path.join(self.cert_dir, user_id)
        filename = os.path.join(user_dir, self.USER_CERT)
        if not os.path.exists(user_dir):
            return "User does not exist"
        if not os.path.exists(filename):
            return "User has no certificate"
        
        # Create revocation object
        user_cert = self.load_certificate(user_dir, self.USER_CERT)
        print("This is the serial number of the revoked certificate: " + str(user_cert.get_serial_number()))
        t_now = self.get_asn1_time()
        t_update = self.get_asn1_time(datetime.timedelta(days=100))
        rvk = crypto.Revoked()
        rvk.set_serial(str(user_cert.get_serial_number()).encode('utf_8')) 
        rvk.set_rev_date(t_now)
        rvk.set_reason(reason)

        # Create updated CRL
        crl = crypto.CRL()
        crl.set_lastUpdate(t_now)
        crl.set_nextUpdate(t_update)
        crl.set_version(1)
        if(self.crl.get_revoked()):
            for r in self.crl.get_revoked():
                crl.add_revoked(r)
        crl.add_revoked(rvk)

        crl.sign(self.certificate, self.private_key, b'sha256')
        self.crl = crl
        self.write_crl(self.crl)
        return "Revoked", self.get_crl_as_pem_str(self.crl)

    def verify_certificate(self, certificate):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate.encode('utf-8'))
        print("This is the serial number of the verified certificate: " + str(cert.get_serial_number()))

        try:
            #Create a certificate store and add your trusted certs
            store = crypto.X509Store()
            store.add_cert(self.root_certificate)
            store.add_cert(self.certificate)
            store.add_crl(self.crl)
            store.add_crl(self.root_crl)
            store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
            store.set_flags(crypto.X509StoreFlags.CRL_CHECK_ALL)

            # Create a certificate context and verify
            store_ctx = crypto.X509StoreContext(store, cert)
            store_ctx.verify_certificate()
            return 'Valid'

        except Exception as e:
            print(e)
            return 'Invalid'

    def get_ca_stats(self):
        nr_certs = self.load_serial_nr()
        revoked = self.crl.get_revoked()
        nr_revokes = 0
        if revoked:
            nr_revokes = len(revoked)
        result = {
            'certificates': nr_certs, 
            'revocations': nr_revokes,
            'cur_serial_nr': nr_certs
            }
        return result

    def archive_private_key(self, user_dir, private_key):
        # Encrypt private_key with a newly generated symmetric data encryption key,
        # then encrypt the symmetric key with the root public key. According to 
        # multiple sources this is the standard procedure.
        private_key_str = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
        sym_key = Fernet.generate_key()
        cipher_suite = Fernet(sym_key)
        cipher_text = cipher_suite.encrypt(private_key_str)
        filename = os.path.join(user_dir, self.USER_PK)
        f = open(filename, "wb").write(cipher_text)
        
        encrypted_sym_key = self.rsa_encrypt(sym_key, 
            self.root_public_key.to_cryptography_key())
        filename = os.path.join(user_dir, self.USER_SK)
        f = open(filename, "wb").write(encrypted_sym_key)

    def rsa_encrypt(self, plaintext, public_key):
        encrypted = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def rsa_decrypt(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def create_self_signed_certificate(self, dir, cert_file, key_file):
        t_now = self.get_asn1_time()
        t_after = self.get_asn1_time(datetime.timedelta(days=5*365))

        cert = crypto.X509()
        cert.set_version(self.VERSION)
        cert.get_subject().CN = "ca@imovies.ch"
        cert.get_subject().O = "iMovies AG"
        cert.set_serial_number(self.serial_nr)
        self.serial_nr += 1
        self.write_serial_nr(self.serial_nr)
        cert.set_notBefore(t_now)
        cert.set_notAfter(t_after)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(self.private_key)
        cert.sign(self.private_key, 'sha256')

        self.write_certificate(self.cert_dir, cert_file, cert)
        self.write_private_key(self.cert_dir, key_file, self.private_key)

    def create_crl(self):
        crl_path = os.path.join(self.cert_dir, self.CRL_FILE)
        crl_path2 = os.path.join(self.cert_dir, 'crl.txt')
        if not os.path.exists(crl_path):
            t_now = self.get_asn1_time()
            t_update = self.get_asn1_time(datetime.timedelta(days=100))
            crl = crypto.CRL()
            crl.set_lastUpdate(t_now)
            crl.set_nextUpdate(t_update)
            crl.set_version(1)
            crl.sign(self.certificate, self.private_key, b'sha256')
            self.write_crl(crl)  
        return self.load_crl(self.CRL_FILE)

    def create_serial_nr(self):
        srnr_filename = os.path.join(self.cert_dir, self.SRNR_FILE)
        if not os.path.exists(srnr_filename):
            self.write_serial_nr(0)
        srnr = self.load_serial_nr()
        return srnr
    
    def create_private_key(self):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        return k

    def load_private_key(self, dir, filename):
        filename = os.path.join(dir, filename)
        f = open(filename, 'rt').read().encode("utf-8")
        k = crypto.load_privatekey(crypto.FILETYPE_PEM, f)
        return k

    def load_certificate(self, dir, filename):
        filename = os.path.join(dir, filename)
        f = open(filename, 'rt').read().encode("utf-8")
        c = crypto.load_certificate(crypto.FILETYPE_PEM, f)
        return c
    
    def load_crl(self, filename):
        filename = os.path.join(self.cert_dir, filename)
        f = open(filename, 'rt').read()
        crl = crypto.load_crl(crypto.FILETYPE_PEM, f)
        return crl
    
    def load_serial_nr(self):
        filename = os.path.join(self.cert_dir, self.SRNR_FILE)
        f = open(filename, 'rt').read()
        return int(f)

    def write_private_key(self, dir, filename, key):
        filename = os.path.join(dir, filename)
        k = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8")
        f = open(filename, "wt").write(k)

    def write_certificate(self, dir, filename, cert):
        filename = os.path.join(dir, filename)
        c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
        f = open(filename, "wt").write(c)

        filename = os.path.join(dir, 'c.txt')
        c = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode("utf-8")
        f = open(filename, "wt").write(c)

    def write_crl(self, crl):
        filename = os.path.join(self.cert_dir, self.CRL_FILE)
        c = crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode("utf-8")
        f = open(filename, "wt").write(c)

        # For Readability and Debugging also dump text version
        filename = os.path.join(self.cert_dir, 'crl.txt')
        c = crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode("utf-8")
        f = open(filename, "wt").write(c)
    
    def get_crl_as_pem_str(self, crl):
        return crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode("utf-8")

    def write_serial_nr(self, srnr):
        filename = os.path.join(self.cert_dir, self.SRNR_FILE)
        f = open(filename, "wt").write(str(srnr))

    def get_current_ts(self):
        return int(datetime.datetime.now().timestamp())

    def get_asn1_time(self, offset = datetime.timedelta(days=0)):
        time = datetime.datetime.now()
        time += offset
        time -= datetime.timedelta(hours=1)
        res = time.strftime('%Y%m%d%H%M%S') + 'Z'
        return res.encode('utf-8')
    