"""
A simple client that uses the Python ACME library to run a test issuance against
a local Boulder server. Usage:

$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
$ python chisel.py foo.com bar.com
"""
import signal
import sys
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import OpenSSL

from acme import challenges
from acme import client as acme_client
from acme import jose
from acme import messages
from acme import standalone

signal.signal(signal.SIGINT, lambda _, __: sys.exit)

def make_client():
  key = jose.JWKRSA(key=jose.ComparableRSAKey(
    rsa.generate_private_key(65537, 2048, default_backend())))

  net = acme_client.ClientNetwork(key, verify_ssl=False,
                                  user_agent="Boulder integration tester")

  # Build client and register account.
  client = acme_client.Client("http://localhost:4000/directory", key=key, net=net)
  account = client.register(messages.NewRegistration.from_data(email="foo@bar.com"))
  client.agree_to_tos(account)
  return client

# Authorize name
def get_chall(client, domain):
  authz = client.request_domain_challenges(domain)
  for chall_body in authz.body.challenges:
    if isinstance(chall_body.chall, challenges.HTTP01):
      return authz, chall_body
  raise "No HTTP-01 challenge found"

def answer_chall(client, chall_body):
  response, validation = chall_body.response_and_validation(client.key)

  answers = set()
  answers.add(standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=chall_body.chall, response=response,
        validation=validation))

  server = standalone.HTTP01Server(("", 5002), answers)
  thread = threading.Thread(target=server.serve_forever)
  thread.start()

  time.sleep(0.1)
  client.answer_challenge(chall_body, response)
  server.shutdown()
  server.server_close()
  thread.join()

def issue(client, authzs):
  domains = [authz.body.identifier.value for authz in authzs]
  pkey = OpenSSL.crypto.PKey()
  pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
  req = OpenSSL.crypto.X509Req()
  req.add_extensions([
      OpenSSL.crypto.X509Extension(
          'subjectAltName',
          critical=False,
          value=', '.join('DNS:' + d for d in domains).encode()
      ),
  ])
  req.set_pubkey(pkey)
  req.set_version(2)
  req.sign(pkey, 'sha256')

  certr, _ = client.poll_and_request_issuance(jose.ComparableX509(req), authzs)

def auth(client, domain):
  authz, chall_body = get_chall(client, domain)
  answer_chall(client, chall_body)
  return authz

def auth_and_issue(domains):
  client = make_client()
  authzs = [auth(client, d) for d in domains]
  issue(client, authzs)

if __name__ == "__main__":
  try:
      auth_and_issue(sys.argv[1:])
  except messages.Error, e:
    print e
    sys.exit(1)
