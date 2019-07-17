"""Crypto utilities."""
import binascii
import logging
import os
import random

import OpenSSL
from OpenSSL import crypto

logger = logging.getLogger(__name__)

domains = ["test.domain.com"]
ALL_OPTIONS = {
    'keys': [(OpenSSL.crypto.TYPE_RSA, 4096), (OpenSSL.crypto.TYPE_RSA, 2048), (OpenSSL.crypto.TYPE_RSA, 1024),
             (OpenSSL.crypto.TYPE_DSA, 2048), (OpenSSL.crypto.TYPE_DSA, 1024)],
    # other types of public keys are not supported by pyopenssl - not sure how to get ECDSA or EdDSA/Ed25519
    'sig_algs': ["MD4",
                 "MD5",
                 "MD5-SHA1",
                 "MDC2",
                 "RIPEMD160",
                 "SHA1",
                 "SHA224",
                 "SHA256",
                 "SHA384",
                 "SHA512",
                 "MD4",
                 "MD5",
                 "MD5-SHA1",
                 "MDC2",
                 "RIPEMD160",
                 "SHA1",
                 "SHA224",
                 "SHA256",
                 "SHA384",
                 "SHA512",
                 "whirlpool",
                 ],
    'extensions': [
        crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=', '.join('DNS:' + d for d in domains).encode('ascii')
        ),
        crypto.X509Extension( # OSCP must staple
            b"1.3.6.1.5.5.7.1.24",
            critical=False,
            value=b"DER:30:03:02:01:05"
        ),
    ],
}


def fuzz(iterations):
    """Generate and fuzz CSR containing a list of domains as subjectAltNames.

    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :returns: a list of buffer PEM-encoded Certificate Signing Requests.
    """
    random.seed(12345)

    csrs = []
    for iteration in range(1,iterations+1):
        options = {
            'key': random.choice(ALL_OPTIONS['keys']),
            'sig_alg': random.choice(ALL_OPTIONS['sig_algs']),
            'extensions': random.sample(ALL_OPTIONS['extensions'], random.randint(0,len(ALL_OPTIONS['extensions'])))
        }
        csrs.append(generate_csr(domains, options))

    return csrs



def generate_csr(options):
    key = OpenSSL.crypto.PKey()
    # key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    key.generate_key(options['key'][0], options['key'][1])
    private_key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

    private_key = crypto.load_privatekey(
        crypto.FILETYPE_PEM, private_key_pem)
    csr = crypto.X509Req()
    csr.add_extensions(options['extensions'])
    csr.set_pubkey(private_key)
    csr.set_version(2)
    csr.sign(private_key, options['sig_alg'])
    return [crypto.dump_certificate_request(
        crypto.FILETYPE_PEM, csr)]


def gen_ss_cert(key, domains, not_before=None,
                validity=(7 * 24 * 60 * 60), force_san=True):
    """Generate new self-signed certificate.

    :type domains: `list` of `unicode`
    :param OpenSSL.crypto.PKey key:
    :param bool force_san:

    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.

    """
    assert domains, "Must provide one or more hostnames for the cert."
    cert = crypto.X509()
    cert.set_serial_number(int(binascii.hexlify(os.urandom(16)), 16))
    cert.set_version(2)

    extensions = [
        crypto.X509Extension(
            b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    ]

    cert.get_subject().CN = domains[0]
    # TODO: what to put into cert.get_subject()?
    cert.set_issuer(cert.get_subject())

    if force_san or len(domains) > 1:
        extensions.append(crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=b", ".join(b"DNS:" + d.encode() for d in domains)
        ))

    cert.add_extensions(extensions)

    cert.gmtime_adj_notBefore(0 if not_before is None else not_before)
    cert.gmtime_adj_notAfter(validity)

    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert

if __name__ == "__main__":
    print(fuzz(["test.com"]))
