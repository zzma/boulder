"""Crypto utilities."""
import binascii
import logging
import os

import OpenSSL
from OpenSSL import crypto

logger = logging.getLogger(__name__)

def fuzz(domains):
    """Generate and fuzz CSR containing a list of domains as subjectAltNames.

    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :returns: a list of buffer PEM-encoded Certificate Signing Requests.
    """
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    private_key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    must_staple = False

    private_key = crypto.load_privatekey(
        crypto.FILETYPE_PEM, private_key_pem)
    csr = crypto.X509Req()
    extensions = [
        crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=', '.join('DNS:' + d for d in domains).encode('ascii')
        ),
    ]
    if must_staple:
        extensions.append(crypto.X509Extension(
            b"1.3.6.1.5.5.7.1.24",
            critical=False,
            value=b"DER:30:03:02:01:05"))
    csr.add_extensions(extensions)
    csr.set_pubkey(private_key)
    csr.set_version(2)
    csr.sign(private_key, 'sha256')
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
