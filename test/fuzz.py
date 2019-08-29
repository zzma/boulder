#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
This file contains basic infrastructure for running the fuzz test cases.
Most test cases are in fuzz.py.
"""
import argparse
import atexit

import startservers


import chisel2
import csr_fuzzer
import config_fuzzer
import traceback

from helpers import *

import challtestsrv
challSrv = challtestsrv.ChallTestServer()


exit_status = 1


def main():
    parser = argparse.ArgumentParser(description='Run integration tests')
    parser.add_argument('--all', dest="run_all", action="store_true",
                        help="run all of the clients' integration tests")
    parser.add_argument('--certbot', dest='run_certbot', action='store_true',
                        help="run the certbot integration tests")
    parser.add_argument('--fuzz', dest="run_fuzz", action="store_true",
                        help="run fuzzing stuff with chisel")
    parser.add_argument('--iter', dest="iters", action="store", type=int, default=5,
                        help="number of fuzzing iterations")
    parser.add_argument('--type', dest="fuzz_type", action="store", type=str, default='csr',
                        help="type of fuzzing (csr/config)")
    parser.add_argument('--load', dest="run_loadtest", action="store_true",
                        help="run load-generator")
    parser.add_argument('--filter', dest="test_case_filter", action="store",
                        help="Regex filter for test cases")
    parser.add_argument('--skip-setup', dest="skip_setup", action="store_true",
                        help="skip integration test setup")
    # allow any ACME client to run custom command for integration
    # testing (without having to implement its own busy-wait loop)
    parser.add_argument('--custom', metavar="CMD", help="run custom command")
    parser.set_defaults(run_all=False, run_certbot=False, run_fuzz=False,
                        run_loadtest=False, test_case_filter="", skip_setup=False)
    args = parser.parse_args()

    if not (args.run_all or args.run_certbot or args.run_fuzz or args.run_loadtest or args.custom is not None):
        raise Exception("must run at least one of the letsencrypt or chisel tests with --all, --certbot, --chisel, --load or --custom")

    config = default_config_dir # TODO: change this to get different configs

    if not startservers.start(race_detection=True, config_dir=config):
        raise Exception("startservers failed")

    if args.fuzz_type.lower() == 'csr':
        run_fuzz_csrs(args.iters)
    elif args.fuzz_type.lower() == 'config':
        run_fuzz_configs(args.iters)

    if args.custom:
        run(args.custom)

    if not startservers.check():
        raise Exception("startservers.check failed")

    global exit_status
    exit_status = 0


def run_fuzz_configs(rounds):
    fuzzy_configs = config_fuzzer.fuzz(rounds)
    # for challenge in ["http-01", "dns-01", "tls-alpn-01"]: #TODO: do i really need these different auth mechanisms?
    for challenge in ["http-01"]: #TODO: do i really need these different auth mechanisms?
        if challenge == "tls-alpn-01":
            challSrv.add_a_record("test.domain.com", ["10.88.88.88"]) # this domain is in config_fuzzer.py

        for config in fuzzy_configs:
            config_fuzzer.write_config(config, "test/fuzz-configs")
            try:
                order = chisel2.auth_and_issue(["test.domain.com"], chall_type=challenge)
                print("CERT", order.fullchain_pem)
            except Exception:
                traceback.print_exc()

        if challenge == "tls-alpn-01":
            challSrv.remove_a_record("test.domain.com") # this domain is in config_fuzzer.py


def run_fuzz_csrs(rounds):
    fuzzy_csrs = csr_fuzzer.fuzz(rounds)
    # for challenge in ["http-01", "dns-01", "tls-alpn-01"]: #TODO: do i really need these different auth mechanisms?
    for challenge in ["http-01"]: #TODO: do i really need these different auth mechanisms?
        if challenge == "tls-alpn-01":
            challSrv.add_a_record("test.domain.com", ["10.88.88.88"]) # this domain is in csr_fuzzer.py

        for csr in fuzzy_csrs:
            print("CSR", csr)
            try:
                order = chisel2.auth_and_issue_csr(csr, chall_type=challenge)
                print("CERT", order.fullchain_pem)
            except Exception:
                traceback.print_exc()

        if challenge == "tls-alpn-01":
            challSrv.remove_a_record("test.domain.com") # this domain is in csr_fuzzer.py


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        raise Exception("%s. Output:\n%s" % (e, e.output))


@atexit.register
def stop():
    if exit_status == 0:
        print("\n\nSUCCESS")
    else:
        print("\n\nFAILURE")
