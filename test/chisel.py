"""
A simple client that uses the Python ACME library to run a test issuance against
a local Boulder server. Usage:

$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
$ python chisel.py foo.com bar.com
"""
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib2

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import OpenSSL

from acme import challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import jose
from acme import messages
from acme import standalone

logger = logging.getLogger()
logger.setLevel(int(os.getenv('LOGLEVEL', 20)))

def make_client(email=None):
  key = jose.JWKRSA(key=jose.ComparableRSAKey(
    rsa.generate_private_key(65537, 2048, default_backend())))

  net = acme_client.ClientNetwork(key, verify_ssl=False,
                                  user_agent="Boulder integration tester")

  # Build client and register account.
  client = acme_client.Client("http://localhost:4000/directory", key=key, net=net)
  account = client.register(messages.NewRegistration.from_data(email=email))
  client.agree_to_tos(account)
  return client

# Authorize name
def get_chall(client, domain):
  authz = client.request_domain_challenges(domain)
  for chall_body in authz.body.challenges:
    if isinstance(chall_body.chall, challenges.HTTP01):
      return authz, chall_body
  raise "No HTTP-01 challenge found"

def http_01_answer(client, chall_body):
  response, validation = chall_body.response_and_validation(client.key)
  return standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=chall_body.chall, response=response,
        validation=validation)

def make_authzs(client, domains):
  authzs, challenges = [], []
  for d in domains:
      authz, chall_body = get_chall(client, d)

      authzs.append(authz)
      challenges.append(chall_body)
  return authzs, challenges

def answer_chall(client, chall_body):
  port = 5002
  server = standalone.HTTP01Server(("", port), answers)
  thread = threading.Thread(target=server.serve_forever)
  thread.start()

  # Loop until the HTTP01Server is ready.
  while True:
    try:
      urllib2.urlopen("http://localhost:%d" % port)
      break
    except urllib2.URLError:
      time.sleep(0.1)
  client.answer_challenge(chall_body, response)
  server.shutdown()
  server.server_close()
  thread.join()

class ValidationError(Exception):
  """Error validating"""
  def __init__(self, domain, problem_type, detail, *args, **kwargs):
    self.domain = domain
    self.problem_type = problem_type
    self.detail = detail

  def __str__(self):
    return "%s: %s: %s" % (self.domain, self.problem_type, self.detail)

def issue(client, authzs, cert_output=None):
  domains = [authz.body.identifier.value for authz in authzs]
  pkey = OpenSSL.crypto.PKey()
  pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
  csr = OpenSSL.crypto.X509Req()
  csr.add_extensions([
      OpenSSL.crypto.X509Extension(
          'subjectAltName',
          critical=False,
          value=', '.join('DNS:' + d for d in domains).encode()
      ),
  ])
  csr.set_pubkey(pkey)
  csr.set_version(2)
  csr.sign(pkey, 'sha256')

  try:
      certr, _ = client.poll_and_request_issuance(jose.ComparableX509(csr), authzs)
  except acme_errors.PollError as error:
      # If we get a PollError, pick the first failed authz and turn it into a more
      # useful ValidationError that contains details we can look for in tests.
      for authz in error.updated:
        updated_authz = json.loads(urllib2.urlopen(authz.uri).read())
        domain = authz.body.identifier.value,
        for c in updated_authz['challenges']:
            if 'error' in c:
                err = c['error']
                raise ValidationError(domain, err['type'], err['detail'])
  if cert_output != None:
    pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certr.body)
    with open(cert_output, 'w') as f:
      f.write(pem)
  return certr

def auth_and_issue(domains, email=None, cert_output=None, client=None):
  if client == None:
      client = make_client(email)
  authzs, challenges = make_authzs(client, domains)
  port = 5002
  answers = set([http_01_answer(client, c) for c in challenges])
  server = standalone.HTTP01Server(("", port), answers)
  thread = threading.Thread(target=server.serve_forever)
  thread.start()

  # Loop until the HTTP01Server is ready.
  while True:
    try:
      urllib2.urlopen("http://localhost:%d" % port)
      break
    except urllib2.URLError:
      time.sleep(0.1)

  try:
      for chall_body in challenges:
        client.answer_challenge(chall_body, chall_body.response(client.key))
      cert_resource = issue(client, authzs, cert_output)
      return cert_resource
  finally:
      server.shutdown()
      server.server_close()
      thread.join()

def expect_problem(problem_type, func):
    ok = False
    try:
        func()
    except ValidationError as e:
        if e.problem_type == problem_type:
            ok = True
        else:
            raise
    except messages.Error as e:
        if problem_type in e.__str__():
            ok = True
        else:
            raise
    if not ok:
        raise Exception("Expected %s, got no error" % problem_type)

if __name__ == "__main__":
  try:
      auth_and_issue(sys.argv[1:])
  except messages.Error, e:
    print e
    sys.exit(1)
