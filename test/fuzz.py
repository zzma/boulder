#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Integration test cases for ACMEv2 as implemented by boulder-wfe2.
"""
import chisel2
import csr_fuzzer
import traceback

from helpers import *

import challtestsrv
challSrv = challtestsrv.ChallTestServer()

fuzzy_csrs = csr_fuzzer.fuzz(5)

def test_fuzz():
    for challenge in ["http-01", "dns-01", "tls-alpn-01"]: #TODO: do i really need these different auth mechanisms?
        if challenge == "tls-alpn-01":
            challSrv.add_a_record("test.domain.com", ["10.88.88.88"]) # this domain is in csr_fuzzer.py

        for csr in fuzzy_csrs:
            print("CSR", csr)
            try:
                order = chisel2.auth_and_issue_csr(csr, chall_type=challenge)
                print(order)
            except Exception:
                traceback.print_exc()


        if challenge == "tls-alpn-01":
            challSrv.remove_a_record("test.domain.com") # this domain is in csr_fuzzer.py