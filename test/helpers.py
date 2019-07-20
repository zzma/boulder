#!/usr/bin/env python2.7
import base64
import os
import urllib2
import time
import re
import random
import json
import socket
import tempfile
import shutil
import atexit
import errno
import subprocess

import challtestsrv

challSrv = challtestsrv.ChallTestServer()
tempdir = tempfile.mkdtemp()

@atexit.register
def stop():
    shutil.rmtree(tempdir)

default_config_dir = os.environ.get('BOULDER_CONFIG_DIR', '')
if default_config_dir == '':
    default_config_dir = 'test/config'
CONFIG_NEXT = default_config_dir.startswith("test/config-next")

def fakeclock(date):
    return date.strftime("%a %b %d %H:%M:%S UTC %Y")

def get_future_output(cmd, date):
    return run(cmd, env={'FAKECLOCK': fakeclock(date)})

def random_domain():
    """Generate a random domain for testing (to avoid rate limiting)."""
    return "rand.%x.xyz" % random.randrange(2**32)

def run(cmd, **kwargs):
    return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, **kwargs)

def fetch_ocsp(request_bytes, url):
    """Fetch an OCSP response using POST, GET, and GET with URL encoding.

    Returns a tuple of the responses.
    """
    ocsp_req_b64 = base64.b64encode(request_bytes)

    # Make the OCSP request three different ways: by POST, by GET, and by GET with
    # URL-encoded parameters. All three should have an identical response.
    get_response = urllib2.urlopen("%s/%s" % (url, ocsp_req_b64)).read()
    get_encoded_response = urllib2.urlopen("%s/%s" % (url, urllib2.quote(ocsp_req_b64, safe = ""))).read()
    post_response = urllib2.urlopen("%s/" % (url), request_bytes).read()

    return (post_response, get_response, get_encoded_response)

def make_ocsp_req(cert_file, issuer_file):
    """Return the bytes of an OCSP request for the given certificate file."""
    ocsp_req_file = os.path.join(tempdir, "ocsp.req")
    # First generate the OCSP request in DER form
    run("openssl ocsp -no_nonce -issuer %s -cert %s -reqout %s" % (
        issuer_file, cert_file, ocsp_req_file))
    with open(ocsp_req_file) as f:
        ocsp_req = f.read()
    return ocsp_req

def ocsp_verify(cert_file, issuer_file, ocsp_response):
    ocsp_resp_file = os.path.join(tempdir, "ocsp.resp")
    with open(ocsp_resp_file, "w") as f:
        f.write(ocsp_response)
    output = run("openssl ocsp -no_nonce -issuer %s -cert %s \
      -verify_other %s -CAfile test/test-root.pem \
      -respin %s" % (issuer_file, cert_file, issuer_file, ocsp_resp_file))
    # OpenSSL doesn't always return non-zero when response verify fails, so we
    # also look for the string "Response Verify Failure"
    verify_failure = "Response Verify Failure"
    if re.search(verify_failure, output):
        print output
        raise Exception("OCSP verify failure")
    return output

def verify_ocsp(cert_file, issuer_file, url, status):
    ocsp_request = make_ocsp_req(cert_file, issuer_file)
    responses = fetch_ocsp(ocsp_request, url)

    # Verify all responses are the same
    for resp in responses:
        if resp != responses[0]:
            raise Exception("OCSP responses differed: %s vs %s" %(
                base64.b64encode(responses[0]), base64.b64encode(resp)))

    # Check response is for the correct certificate and is correct
    # status
    resp = responses[0]
    verify_output = ocsp_verify(cert_file, issuer_file, resp)
    if not re.search("%s: %s" % (cert_file, status), verify_output):
        print verify_output
        raise Exception("OCSP response wasn't '%s'" % status)

def reset_akamai_purges():
    urllib2.urlopen("http://localhost:6789/debug/reset-purges", "{}")

def verify_akamai_purge():
    deadline = time.time() + 0.25
    while True:
        time.sleep(0.05)
        if time.time() > deadline:
            raise Exception("Timed out waiting for Akamai purge")
        response = urllib2.urlopen("http://localhost:6789/debug/get-purges")
        purgeData = json.load(response)
        if len(purgeData["V3"]) is not 1:
            continue
        break
    reset_akamai_purges()

twenty_days_ago_functions = [ ]

def register_twenty_days_ago(f):
    """Register a function to be run during "setup_twenty_days_ago." This allows
       test cases to define their own custom setup.
    """
    twenty_days_ago_functions.append(f)

def setup_twenty_days_ago():
    """Do any setup that needs to happen 20 day in the past, for tests that
       will run in the 'present'.
    """
    for f in twenty_days_ago_functions:
        f()

def waitport(port, prog, perTickCheck=None):
    """Wait until a port on localhost is open."""
    for _ in range(1000):
        try:
            time.sleep(0.1)
            if perTickCheck is not None and not perTickCheck():
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', port))
            s.close()
            return True
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print "Waiting for debug port %d (%s)" % (port, prog)
            else:
                raise
    raise Exception("timed out waiting for debug port %d (%s)" % (port, prog))
