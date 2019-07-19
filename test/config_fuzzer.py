"""Crypto utilities."""
import copy
import json
import logging
import os
import random

logger = logging.getLogger(__name__)

domains = ["test.domain.com"]
ALL_OPTIONS = {
    'usages': [
        # KeyUsage contains a mapping of string names to key usages.
        "signing",
        "digital signature",
        "content commitment",
        "key encipherment",
        "key agreement",
        "data encipherment",
        "cert sign",
        "crl sign",
        "encipher only",
        "decipher only",
        # ExtKeyUsage contains a mapping of string names to extended key
        "any",
        "server auth",
        "client auth",
        "code signing",
        "email protection",
        "s/mime",
        "ipsec end system",
        "ipsec tunnel",
        "ipsec user",
        "timestamping",
        "ocsp signing",
        "microsoft sgc",
        "netscape sgc",
    ],
    # other types of public keys are not supported by pyopenssl - not sure how to get ECDSA or EdDSA/Ed25519
    'policies': [
        {
            "ID": "2.23.140.1.2.1"
        },
        {
            "ID": "1.2.3.4",
            "Qualifiers": [{
                "type": "id-qt-cps",
                "value": "http://example.com/cps"
            }, {
                "type": "id-qt-unotice",
                "value": "Do What Thou Wilt"
            }]
        },
    ],
    'CSRWhitelist': [
        "Subject",
        "PublicKeyAlgorithm",
        "PublicKey",
        "SignatureAlgorithm",
        "DNSNames",
        "IPAddresses",
        "EmailAddresses",
        "URIs",
    ],
    'allowed_extensions': [
        "2.5.29.14", # subjectKeyIdentifier
        "2.5.29.15", # keyUsage
        "2.5.29.37", # extKeyUsage
        "2.5.29.35", # authorityKeyIdentifier
        "2.5.29.19", # basicConstraints
        "2.5.29.17", # subjectAltName
        "2.5.29.18", # issuerAltName
        "2.5.29.32", # certificatePoliciesExt
        "2.5.29.30", # nameConstraints
        "2.5.29.31", # CRLDistributionPoints
        "1.3.6.1.5.5.7.1.1", # authorityInfoAccess
        "1.3.6.1.4.1.11129.2.4.2", # signedCertificateTimestampList
        "1.3.6.1.5.5.7.48.4", # OCSPNocheck
        "2.5.29.36", # policyConstraints
        "2.5.29.33", # policyMappings
        "2.5.29.16", # privateKeyUsagePeriod
        "2.5.29.9", # subjectDirectoryAttributes
    ],
}

CONFIG_TEMPLATE = {
    "ca": {
        "serialPrefix": 255,
        "rsaProfile": "rsaEE",
        "ecdsaProfile": "ecdsaEE",
        "debugAddr": ":8001",
        "weakKeyDirectory": "test/example-weak-keys.json",
        "tls": {
            "caCertFile": "test/grpc-creds/minica.pem",
            "certFile": "test/grpc-creds/ca.boulder/cert.pem",
            "keyFile": "test/grpc-creds/ca.boulder/key.pem"
        },
        "saService": {
            "serverAddress": "sa.boulder:9095",
            "timeout": "15s"
        },
        "grpcCA": {
            "address": ":9093",
            "clientNames": [
                "ra.boulder"
            ]
        },
        "grpcOCSPGenerator": {
            "address": ":9096",
            "clientNames": [
                "ocsp-updater.boulder"
            ]
        },
        "Issuers": [{
            "ConfigFile": "test/test-ca.key-pkcs11.json",
            "CertFile": "test/test-ca2.pem",
            "NumSessions": 2
        }, {
            "ConfigFile": "test/test-ca.key-pkcs11.json",
            "CertFile": "test/test-ca.pem",
            "NumSessions": 2
        }],
        "expiry": "2160h",
        "backdate": "1h",
        "lifespanOCSP": "96h",
        "maxNames": 100,
        "hostnamePolicyFile": "test/hostname-policy.yaml",
        "cfssl": {
            "signing": {
                "profiles": {
                    "rsaEE": {
                        # "usages": [], TEMPLATED
                        "backdate": "1h",
                        "ca_constraint": { "is_ca": False },
                        "issuer_urls": [
                            "http://boulder:4430/acme/issuer-cert"
                        ],
                        "ocsp_url": "http://127.0.0.1:4002/",
                        "crl_url": "http://example.com/crl",
                        # "policies": [], TEMPLATED
                        "expiry": "2160h",
                        # "CSRWhitelist": {}, TEMPLATED
                        "ClientProvidesSerialNumbers": True,
                        # "allowed_extensions": [], TEMPLATED
                    },
                    "ecdsaEE": {
                        # "usages": [], TEMPLATED
                        "backdate": "1h",
                        "is_ca": False,
                        "issuer_urls": [
                            "http://127.0.0.1:4000/acme/issuer-cert"
                        ],
                        "ocsp_url": "http://127.0.0.1:4002/",
                        "crl_url": "http://example.com/crl",
                        # "policies": [], TEMPLATED
                        "expiry": "2160h",
                        # "CSRWhitelist": {}, TEMPLATED
                        "ClientProvidesSerialNumbers": True,
                        # "allowed_extensions": [], TEMPLATED
                    }
                },
                "default": {
                    "usages": [
                        "digital signature"
                    ],
                    "expiry": "8760h"
                }
            }
        },
        "maxConcurrentRPCServerRequests": 100000,
        "features": {
        }
    },

    "pa": {
        "challenges": {
            "http-01": True,
            "dns-01": True
        }
    },

    "syslog": {
        "stdoutlevel": 6,
        "sysloglevel": 4
    }
}


def fuzz(iterations):
    """Generate and fuzz CSR containing a list of domains as subjectAltNames.

    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :returns: a list of buffer PEM-encoded Certificate Signing Requests.
    """
    random.seed(1234)

    configs = []
    for iteration in range(1, iterations + 1):
        sample = random.sample(ALL_OPTIONS['CSRWhitelist'], random.randint(0, len(ALL_OPTIONS['CSRWhitelist'])))
        csr_whitelist = {}
        for item in sample:
            csr_whitelist[item] = True

        options = {
            'usages': random.sample(ALL_OPTIONS['usages'], random.randint(0, len(ALL_OPTIONS['usages']))),
            'policies': random.sample(ALL_OPTIONS['policies'], random.randint(0, len(ALL_OPTIONS['policies']))),
            'CSRWhitelist': csr_whitelist,
            'allowed_extensions': random.sample(ALL_OPTIONS['allowed_extensions'], random.randint(0, len(ALL_OPTIONS['allowed_extensions']))),
        }

        # TODO: implement better mutation logic / at least memoize

        print(options)
        try:
            configs.append(generate_config(options))
        except Exception as e:
            raise e

    return configs


def generate_config(options):
    # write config to a json file in config_dir
    new_config = copy.deepcopy(CONFIG_TEMPLATE)
    rsaConfig = new_config['ca']['cfssl']['signing']['profiles']['rsaEE']
    rsaConfig['usages'] = options['usages']
    rsaConfig['policies'] = options['policies']
    rsaConfig['CSRWhitelist'] = options['CSRWhitelist']
    rsaConfig['allowed_extensions'] = options['allowed_extensions']

    ecdsaConfig = new_config['ca']['cfssl']['signing']['profiles']['ecdsaEE']
    ecdsaConfig['usages'] = options['usages']
    ecdsaConfig['policies'] = options['policies']
    ecdsaConfig['CSRWhitelist'] = options['CSRWhitelist']
    ecdsaConfig['allowed_extensions'] = options['allowed_extensions']

    return new_config

def write_config(config, config_dir):
    # write config to the appropriate files
    with open(os.path.join(config_dir, 'ca-a.json'), 'w') as f1, open(os.path.join(config_dir, 'ca-a.json'), 'w') as f2:
        json.dump(config, f1, indent=4, ensure_ascii=False)
        json.dump(config, f2, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    print(fuzz(10))
