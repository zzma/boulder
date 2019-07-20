#!/bin/bash
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
if type realpath >/dev/null 2>&1 ; then
  cd $(realpath $(dirname $0))
fi

set -exo pipefail
TRAVIS=${TRAVIS:-false}

# The list of segments to run. To run only some of these segments, pre-set the
# RUN variable with the ones you want (see .travis.yml for an example).
# Order doesn't matter. Note: gomod-vendor is specifically left out of the
# defaults, because we don't want to run it locally (it could delete local
# state) We also omit coverage by default on local runs because it generates
# artifacts on disk that aren't needed.
RUN=${RUN:-lints unit integration}

function run_and_expect_silence() {
  echo "$@"
  result_file=$(mktemp -t bouldertestXXXX)
  "$@" 2>&1 | tee ${result_file}

  # Fail if result_file is nonempty.
  if [ -s ${result_file} ]; then
    rm ${result_file}
    exit 1
  fi
  rm ${result_file}
}

function run_unit_tests() {
  if [ "${TRAVIS}" == "true" ]; then
    # Run the full suite of tests once with the -race flag. Since this isn't
    # running tests individually we can't collect coverage information.
    echo "running test suite with race detection"
    go test -race -p 1 ./...
  else
    # When running locally, we skip the -race flag for speedier test runs. We
    # also pass -p 1 to require the tests to run serially instead of in
    # parallel. This is because our unittests depend on mutating a database and
    # then cleaning up after themselves. If they run in parallel, they can fail
    # spuriously because one test is modifying a table (especially
    # registrations) while another test is reading it.
    # https://github.com/letsencrypt/boulder/issues/1499
    go test -p 1 ./...
  fi
}

function run_test_coverage() {
  # Run each test by itself for Travis, so we can get coverage. We skip using
  # the -race flag here because we have already done a full test run with
  # -race in `run_unit_tests` and it adds substantial overhead to run every
  # test with -race independently
  echo "running test suite with coverage enabled and without race detection"
  go test -p 1 -cover -coverprofile=${dir}.coverprofile ./...

  # Gather all the coverprofiles
  gover

  # We don't use the run function here because sometimes goveralls fails to
  # contact the server and exits with non-zero status, but we don't want to
  # treat that as a failure.
  goveralls -v -coverprofile=gover.coverprofile -service=travis-ci
}

#
# Run various linters.
#
if [[ "$RUN" =~ "lints" ]] ; then
  run_and_expect_silence go vet ./...
  # Run gofmt instead of go fmt because of
  # https://github.com/golang/go/issues/31976
  run_and_expect_silence bash -c "find . -name '*.go' -not -path './vendor/*' -print | xargs -n1 gofmt -l"
  run_and_expect_silence ./test/test-no-outdated-migrations.sh
  ineffassign .
  python test/grafana/lint.py

  run_and_expect_silence errcheck \
    -ignore fmt:Fprintf,fmt:Fprintln,fmt:Fprint,io:Write,os:Remove,net/http:Write \
    $(go list -f '{{ .ImportPath }}' ./... | grep -v test)
fi

#
# Unit Tests.
#
if [[ "$RUN" =~ "unit" ]] ; then
  run_unit_tests
fi

#
# Unit Test Coverage.
#
if [[ "$RUN" =~ "coverage" ]] ; then
  run_test_coverage
fi

#
# Integration tests
#
if [[ "$RUN" =~ "integration" ]] ; then
  args=("--chisel")
  if [[ "${INT_SKIP_LOAD:-}" == "" ]]; then
    args+=("--load")
  fi
  if [[ "${INT_FILTER:-}" != "" ]]; then
    args+=("--filter" "${INT_FILTER}")
  fi
  if [[ "${INT_SKIP_SETUP:-}" =~ "true" ]]; then
    args+=("--skip-setup")
  fi

  source ${CERTBOT_PATH:-/certbot}/${VENV_NAME:-venv}/bin/activate
  DIRECTORY=http://boulder:4000/directory \
    python2 test/integration-test.py "${args[@]}"
fi

#
# Fuzzing tests
#
if [[ "$RUN" =~ "fuzz" ]] ; then
  args=("--fuzz")
  if [["$ITER" -gt 0 ]]; then
    args+=("--iter $ITER")
  else
    args+=("--iter 10")
  fi
  if [[ "${INT_SKIP_LOAD:-}" == "" ]]; then
    args+=("--load")
  fi
  if [[ "${INT_FILTER:-}" != "" ]]; then
    args+=("--filter" "${INT_FILTER}")
  fi
  if [[ "${INT_SKIP_SETUP:-}" =~ "true" ]]; then
    args+=("--skip-setup")
  fi

  source ${CERTBOT_PATH:-/certbot}/${VENV_NAME:-venv}/bin/activate
  DIRECTORY=http://boulder:4000/directory \
    python2 test/fuzz.py "${args[@]}"
fi



# Test that just ./start.py works, which is a proxy for testing that
# `docker-compose up` works, since that just runs start.py (via entrypoint.sh).
if [[ "$RUN" =~ "start" ]] ; then
  ./start.py &
  for I in $(seq 1 100); do
    sleep 1
    curl http://localhost:4000/directory && break
  done
  if [[ $I = 100 ]]; then
    echo "Boulder did not come up after ./start.py."
  fi
fi

# Run go mod vendor (happens only in Travis) to check that the versions in
# vendor/ really exist in the remote repo and match what we have.
if [[ "$RUN" =~ "gomod-vendor" ]] ; then
  go mod vendor
  git diff --exit-code
fi

# Run generate to make sure all our generated code can be re-generated with
# current tools.
# Note: Some of the tools we use seemingly don't understand ./vendor yet, and
# so will fail if imports are not available in $GOPATH. So, in travis, this
# always needs to run after `godep restore`.
if [[ "$RUN" =~ "generate" ]] ; then
  # Additionally, we need to run go install before go generate because the stringer command
  # (using in ./grpc/) checks imports, and depends on the presence of a built .a
  # file to determine an import really exists. See
  # https://golang.org/src/go/internal/gcimporter/gcimporter.go#L30
  # Without this, we get error messages like:
  #   stringer: checking package: grpc/bcodes.go:6:2: could not import
  #     github.com/letsencrypt/boulder/probs (can't find import:
  #     github.com/letsencrypt/boulder/probs)
  go install ./probs
  go install ./vendor/google.golang.org/grpc/codes
  run_and_expect_silence go generate ./...
  run_and_expect_silence git diff --exit-code $(ls | grep -v Godeps)
fi

if [[ "$RUN" =~ "rpm" ]]; then
  make rpm
fi
