#!/bin/bash
# Runs every test suite of P4sim and every example in examples-to-run.py, each
# with ./test.py, and prints a summary. Run it from anywhere after ./ns3 build;
# it exits with 1 if anything fails.

cd "$(dirname "$0")/../../.." || exit 1
p4sim=contrib/p4sim

suites=$(grep -ho 'TestSuite *( *"[^"]*"' $p4sim/test/*.cc | sed 's/.*"\(.*\)"/\1/' | sort -u)
examples=$(python3 -c "
exec(open('$p4sim/test/examples-to-run.py').read())
print('\n'.join(sorted({e[0].split()[0] for e in cpp_examples})))")

if [ -z "$suites" ] || [ -z "$examples" ]; then
    echo "No test suites or examples found"
    exit 1
fi

failed=""
run() {
    if ./test.py --no-build "$@" > /tmp/p4sim-test.log 2>&1 && grep -q '1 passed' /tmp/p4sim-test.log; then
        echo "PASS $*"
    else
        echo "FAIL $*"
        failed="$failed $*"
    fi
}

for s in $suites; do run -s "$s"; done
for e in $examples; do run --example="$e"; done

echo "$(echo "$suites" | wc -l) suites, $(echo "$examples" | wc -l) examples"
if [ -n "$failed" ]; then
    echo "Failed:$failed"
    exit 1
fi
echo "All passed"
