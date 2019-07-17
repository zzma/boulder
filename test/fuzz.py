#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Integration test cases for ACMEv2 as implemented by boulder-wfe2.
"""
import chisel2
import csr_fuzzer
from helpers import *

import challtestsrv
challSrv = challtestsrv.ChallTestServer()

challSrv.add_a_record("test.domain.com", ["10.88.88.88"])
fuzzy_csrs = csr_fuzzer.fuzz(["test.domain.com"])


chisel2.auth_and_issue_csr(csr, chall_type=challenge)
def test_fuzz():
    for challenge in ["http-01", "dns-01", "tls-alpn-01"]:
        for csr in fuzzy_csrs:
            chisel2.auth_and_issue_csr(csr, chall_type=challenge)