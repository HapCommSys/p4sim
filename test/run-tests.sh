#!/bin/bash
# Runs every test suite of P4sim and every example in examples-to-run.py, each
# with ./test.py, and prints a summary. Run it from anywhere after ./ns3 build;
# it exits with 1 if anything fails. An example that is not built (such as
# p4-ipv4-animation without netanim) is skipped.

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

log=$(mktemp) || exit 1
trap 'rm -f "$log"' EXIT
failed=""
skipped=""
run() {
    if ./test.py --no-build "$@" > "$log" 2>&1 && grep -q '1 passed' "$log"; then
        echo "PASS $*"
    elif grep -q '^No example matching the name' "$log"; then
        echo "SKIP $* (not built)"
        skipped="$skipped $*"
    else
        echo "FAIL $*"
        failed="$failed $*"
    fi
}

for s in $suites; do run -s "$s"; done
for e in $examples; do run --example="$e"; done

echo "$(echo "$suites" | wc -l) suites, $(echo "$examples" | wc -l) examples"
[ -z "$skipped" ] || echo "Skipped (not built):$skipped"
if [ -n "$failed" ]; then
    echo "Failed:$failed"
    exit 1
fi
echo "All passed"
