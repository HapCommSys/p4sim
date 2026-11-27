#!/bin/bash
# Runs every test suite of P4sim and every entry of examples-to-run.py, with its
# arguments, and prints a summary. Run it from anywhere after ./ns3 build; it
# exits with 1 if anything fails. An example that is not built (such as
# p4-ipv4-animation without netanim) is skipped.
#
# The suites and the entries without arguments run with ./test.py. test.py
# --example takes no arguments, so an entry with arguments runs with ./ns3 run in
# a scratch directory, and its exit code decides: the examples check their
# results and exit with 1 if a check fails.

cd "$(dirname "$0")/../../.." || exit 1
p4sim=contrib/p4sim

suites=$(grep -ho 'TestSuite *( *"[^"]*"' $p4sim/test/*.cc | sed 's/.*"\(.*\)"/\1/' | sort -u)
examples=$(python3 -c "
exec(open('$p4sim/test/examples-to-run.py').read())
print('\n'.join(sorted({e[0] for e in cpp_examples})))")

if [ -z "$suites" ] || [ -z "$examples" ]; then
    echo "No test suites or examples found"
    exit 1
fi

log=$(mktemp) || exit 1
scratch=$(mktemp -d) || exit 1
trap 'rm -rf "$log" "$scratch"' EXIT
failed=()
skipped=()
pass() { echo "PASS $1"; }
skip() {
    echo "SKIP $1 (not built)"
    skipped+=("$1")
}
fail() {
    echo "FAIL $1"
    failed+=("$1")
}

# One suite (-s <name>) or one example without arguments (--example=<name>)
run() {
    if ./test.py --no-build "$@" > "$log" 2>&1 < /dev/null && grep -q '1 passed' "$log"; then
        pass "$*"
    elif grep -q '^No example matching the name' "$log"; then
        skip "$*"
    else
        fail "$*"
    fi
}

# One entry of examples-to-run.py: its example name and maybe arguments
run_example() {
    case "$1" in
    *" "*)
        if ./ns3 run --no-build --cwd="$scratch" "$1" > "$log" 2>&1 < /dev/null; then
            pass "--example=$1"
        elif grep -q "Couldn't find the specified program" "$log"; then
            skip "--example=$1"
        else
            fail "--example=$1"
        fi
        ;;
    *) run --example="$1" ;;
    esac
}

for s in $suites; do run -s "$s"; done
while IFS= read -r e; do run_example "$e"; done <<< "$examples"

names=$(echo "$examples" | cut -d' ' -f1 | sort -u | wc -l)
echo "$(echo "$suites" | wc -l) suites, $names examples in $(echo "$examples" | wc -l) runs"
[ ${#skipped[@]} -eq 0 ] || printf 'Skipped (not built): %s\n' "${skipped[@]}"
if [ ${#failed[@]} -gt 0 ]; then
    printf 'Failed: %s\n' "${failed[@]}"
    exit 1
fi
echo "All passed"
