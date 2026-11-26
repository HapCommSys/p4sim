#!/bin/bash
# Quick installation of P4sim on Ubuntu 24.04 or 26.04: installs what P4sim
# needs, then builds and tests ns-3 with P4sim. About 6 minutes on 16 cores.
#
#   Ubuntu packages  compilers, CMake, Ninja, ccache, Thrift and the libraries
#                    of BMv2 and P4sim
#   p4c              the prebuilt package of p4lang (repository home:p4lang on
#                    download.opensuse.org)
#   BMv2 1.15.8      built from source and installed in /usr/local, where P4sim
#                    finds its headers and Thrift service libraries: shared
#                    libraries and the targets simple_switch and psa_switch
#   ns-3 + P4sim     the ns-3 modules P4sim needs, with P4sim's tests and
#                    examples (no netanim, so p4-ipv4-animation is not built)
#
# Run it from its place in an ns-3 tree, as a normal user; it asks for sudo:
#
#   git clone --depth 1 -b ns-3.39 https://github.com/nsnam/ns-3-dev-git.git ns3.39
#   git clone https://github.com/HapCommSys/p4sim.git ns3.39/contrib/p4sim
#   ns3.39/contrib/p4sim/install.sh
#
#   install.sh [step ...]  steps: apt bmv2 ns3 test; without a step it runs all
#                          four, and downloads and builds BMv2 while apt and
#                          ns-3 are busy. The step test alone needs no sudo.
#
# Settings (environment variables):
#   JOBS          parallel build jobs (default: one per CPU)
#   NS3_MODULES   ns-3 modules to build (default "p4sim;nix-vector-routing",
#                 plus the modules they depend on). An ns-3 tree that is
#                 configured already keeps its modules unless this is set.
#   BMV2_REBUILD  1: build and install BMv2 even if one is installed
#   LOGDIR        log files (default ~/.cache/p4sim-install)

set -euo pipefail
JOBS=${JOBS:-$(nproc)}
BMV2_REBUILD=${BMV2_REBUILD:-0}
LOGDIR=${LOGDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/p4sim-install}
BMV2_VERSION=1.15.8
BMV2_RECIPE="shared-only,simple_switch+psa_switch"   # a change rebuilds BMv2
BMV2_SRC=""                                          # a new private directory per build
BMV2_STAMP=/usr/local/share/p4sim/bmv2.stamp
# The Python that gets BMv2's Python modules and python3-thrift: the system's,
# even if a virtual environment or conda is active
PY=/usr/bin/python3
# ns-3 modules P4sim depends on: built while BMv2 configures
NS3_DEP_MODULES="nix-vector-routing csma point-to-point applications bridge"
P4SIM=$(cd "$(dirname "$0")" && pwd)
NS3=$(cd "$P4SIM/../.." && pwd)
APT="env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o Acquire::Retries=5 -o Dpkg::Use-Pty=0 --no-install-recommends"

die() { echo "install.sh: $*" >&2; exit 1; }
[ -x "$NS3/ns3" ] && [ "$(basename "$(dirname "$P4SIM")")" = contrib ] \
    || die "run me from an ns-3 tree, as <ns-3>/contrib/p4sim/install.sh (see the top of this file)"

STEPS=("${@:-all}")
NEED_ROOT=0
for s in "${STEPS[@]}"; do
    case "$s" in
        test) ;;
        all | apt | bmv2 | ns3) NEED_ROOT=1 ;;
        *) die "unknown step $s (steps: apt bmv2 ns3 test)" ;;
    esac
done

# The modules are set for a new ns-3 configuration, when NS3_MODULES is given, or
# when the configuration leaves P4sim out; otherwise the tree keeps its modules
NS3_CACHE=$NS3/cmake-cache/CMakeCache.txt
NS3_SET_MODULES=0
if [ ! -f "$NS3_CACHE" ] || [ -n "${NS3_MODULES+set}" ]; then
    NS3_SET_MODULES=1
else
    enabled=$(sed -n 's/^NS3_ENABLED_MODULES:STRING=//p' "$NS3_CACHE")
    if [ -n "$enabled" ] && ! printf '%s\n' "$enabled" | tr ';' '\n' | grep -qx p4sim; then
        NS3_SET_MODULES=1
    fi
fi
NS3_MODULES=${NS3_MODULES:-p4sim;nix-vector-routing}

# WSL appends the Windows PATH (/mnt/c/...). ./ns3 configure stores PATH and
# test.py adds it to LD_LIBRARY_PATH, which makes every start of a runtime CLI
# slow; leave it out.
if grep -qi microsoft /proc/version 2>/dev/null; then
    PATH=$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '^/mnt/' | paste -sd: -)
    export PATH
fi

mkdir -p "$LOGDIR"
LOGDIR=$(cd "$LOGDIR" && pwd)
LOG=$LOGDIR/install.log
exec > >(tee -a "$LOG") 2>&1

PYENV=${VIRTUAL_ENV:-${CONDA_PREFIX:-}}
if [ -n "$PYENV" ]; then
    echo "Note: the Python environment $PYENV is active. BMv2's Python modules go to"
    echo "the system Python; the runtime CLIs (simple_switch_CLI, ...) run the python3"
    echo "found first in PATH, so this environment needs the package thrift"
    echo "(pip install thrift), or deactivate it."
fi

if [ "$(id -u)" = 0 ] || [ "$NEED_ROOT" = 0 ]; then
    SUDO=
else
    command -v sudo >/dev/null || die "needs sudo, or run it as root"
    sudo true || die "sudo failed"
    # keep the sudo ticket while the build runs
    ( while kill -0 $$ 2> /dev/null; do sudo -n true; sleep 50; done ) > /dev/null 2>&1 &
    trap "kill $! 2> /dev/null" EXIT
    SUDO=sudo
fi

T0=$(date +%s)
TIMES=()
step() { echo; echo "=== $(date +%T) [+$(( $(date +%s) - T0 ))s] $*"; }
# run_logged NAME CMD...: output to $LOGDIR/NAME.log, its end on failure
run_logged() {
    local name=$1; shift
    "$@" > "$LOGDIR/$name.log" 2>&1 || { tail -n 60 "$LOGDIR/$name.log"; echo "FAILED: $name (log: $LOGDIR/$name.log)"; return 1; }
}
# wait_bg PID NAME: wait for a part that ran in the background, show its log
wait_bg() {
    if wait "$1"; then cat "$LOGDIR/$2.log"; else cat "$LOGDIR/$2.log"; die "FAILED: $2"; fi
}

do_apt() {
    step "apt: packages, and p4c from the p4lang repository"
    . /etc/os-release
    case "$ID $VERSION_ID" in
        "ubuntu 24.04" | "ubuntu 26.04") ;;
        *) echo "Warning: tested on Ubuntu 24.04 and 26.04 only, this is ${PRETTY_NAME:-unknown}" ;;
    esac
    local repo="https://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}"
    local key=/etc/apt/keyrings/home-p4lang.gpg tmpkey
    if ! command -v curl >/dev/null || ! command -v gpg >/dev/null; then
        $SUDO apt-get -q update
        $SUDO $APT install ca-certificates curl gpg
    fi
    # the key replaces an older one only once it is downloaded
    tmpkey=$(mktemp)
    if ! curl -fsSL "$repo/Release.key" | gpg --dearmor > "$tmpkey" || [ ! -s "$tmpkey" ]; then
        rm -f "$tmpkey"
        die "cannot download the key of $repo"
    fi
    $SUDO install -d -m 0755 /etc/apt/keyrings
    $SUDO install -m 0644 "$tmpkey" "$key"
    rm -f "$tmpkey"
    echo "deb [signed-by=$key] $repo/ /" | $SUDO tee /etc/apt/sources.list.d/home-p4lang.list > /dev/null
    $SUDO apt-get -q -o Acquire::Retries=5 update
    $SUDO $APT install \
        ca-certificates curl gpg git \
        build-essential autoconf automake libtool pkg-config cmake ninja-build ccache \
        python3 python-is-python3 python3-thrift \
        libboost-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev \
        libgmp-dev libjsoncpp-dev libpcap-dev libxxhash-dev libnanomsg-dev \
        libthrift-dev thrift-compiler libprotobuf-dev protobuf-compiler \
        p4lang-p4c
    p4c --version | head -n 1
}

# ns-3.39's ./ns3 does not run on Python 3.14 (Ubuntu 26.04): its argparse
# rejects positional arguments with action="store_true", which ./ns3 uses to
# mark the sub-command. set_defaults(<name>=True) has the same effect; later ns-3
# releases made the same change.
ns3_fix() {
    if (cd "$NS3" && ./ns3 --help > /dev/null 2>&1); then return; fi
    step "ns3fix: make ./ns3 run on $(python3 --version)"
    "$PY" - "$NS3/ns3" <<'PY'
import re, sys
path = sys.argv[1]
src = open(path).read()
pat = re.compile(r'(\w+)\.add_argument\(\s*\x27(\w+)\x27,\s*'
                 r'(?:help=\x27[^\x27]*\x27,\s*)?'
                 r'action=[\x22\x27]store_true[\x22\x27],\s*default=False\)')
new, n = pat.subn(lambda m: f'{m.group(1)}.set_defaults({m.group(2)}=True)', src)
if n:
    open(path, 'w').write(new)
print(f'ns3: {n} sub-command arguments changed')
PY
    (cd "$NS3" && ./ns3 --help > /dev/null) || die "./ns3 still does not run"
    echo "./ns3 --help: OK"
}

bmv2_want() { echo "$BMV2_VERSION $BMV2_RECIPE"; }
# What P4sim uses of a BMv2 in /usr/local (set_pkg_config_env.sh, CMakeLists.txt)
bmv2_usable() {
    local f
    for f in /usr/local/include/bm/bm_sim /usr/local/lib/libbmall.so \
             /usr/local/lib/libsimpleswitch_thrift.so /usr/local/lib/libpsaswitch_thrift.so \
             /usr/local/bin/simple_switch /usr/local/bin/simple_switch_CLI \
             /usr/local/bin/psa_switch_CLI; do
        [ -e "$f" ] || return 1
    done
}
# 0 if BMv2 must be built: BMV2_REBUILD=1, or neither this script's BMv2 nor
# another usable BMv2 is installed in /usr/local
bmv2_needed() {
    [ "$BMV2_REBUILD" != 1 ] || return 0
    if [ "$(cat "$BMV2_STAMP" 2>/dev/null)" = "$(bmv2_want)" ]; then
        if bmv2_usable && "$PY" -c 'import runtime_CLI, sswitch_runtime, pswitch_runtime' 2>/dev/null; then
            return 1
        fi
        return 0
    fi
    if [ ! -e "$BMV2_STAMP" ] && bmv2_usable; then return 1; fi
    return 0
}
bmv2_note() {
    if [ -e "$BMV2_STAMP" ]; then
        step "bmv2: already installed ($(cat "$BMV2_STAMP"))"
    else
        step "bmv2: using the BMv2 in /usr/local: $(/usr/local/bin/simple_switch --version)"
        echo "(BMV2_REBUILD=1 replaces it with BMv2 $BMV2_VERSION)"
    fi
}

bmv2_new_src() { BMV2_SRC=$(mktemp -d "${TMPDIR:-/tmp}/p4sim-bmv2.XXXXXX"); }

bmv2_fetch() {
    step "bmv2: download $BMV2_VERSION"
    git -c advice.detachedHead=false clone -q --depth 1 -b "$BMV2_VERSION" \
        https://github.com/p4lang/behavioral-model.git "$BMV2_SRC"
}

bmv2_prepare() {
    step "bmv2: autogen, configure (shared libraries only)"
    [ -d "$BMV2_SRC/.git" ] || bmv2_fetch
    cd "$BMV2_SRC"
    ./autogen.sh > /dev/null
    ./configure -q --with-thrift --disable-static --disable-dependency-tracking \
        CC="ccache gcc" CXX="ccache g++" CFLAGS="-O2 -g0" CXXFLAGS="-O2 -g0"
    # only the targets P4sim uses (not pna_nic, l2_switch, simple_router, ...)
    sed -i 's/^SUBDIRS = .*/SUBDIRS = simple_switch psa_switch/' targets/Makefile
    grep -q '^SUBDIRS = simple_switch psa_switch$' targets/Makefile
    cd "$NS3"
}

bmv2_build() {
    step "bmv2: build and install in /usr/local"
    local pydir
    pydir=$("$PY" -c 'import site; print(site.getsitepackages()[0])')
    cd "$BMV2_SRC"
    # pythondir for make too: the runtime CLIs add it to sys.path
    run_logged bmv2-make make -s -j"$JOBS" pythondir="$pydir" pyexecdir="$pydir"
    # headers of an earlier BMv2 in /usr/local
    $SUDO rm -rf /usr/local/include/bm
    run_logged bmv2-install $SUDO make -s install-strip pythondir="$pydir" pyexecdir="$pydir"
    $SUDO ldconfig
    cd "$NS3"
    $SUDO rm -rf "$BMV2_SRC"
    $SUDO install -d "$(dirname "$BMV2_STAMP")"
    bmv2_want | $SUDO tee "$BMV2_STAMP" > /dev/null
    simple_switch --version
    "$PY" -c 'import runtime_CLI, sswitch_runtime, pswitch_runtime' || die "BMv2's Python modules do not import"
    echo "BMv2 Python modules: OK"
}

do_bmv2() {
    if ! bmv2_needed; then bmv2_note; return; fi
    bmv2_new_src
    bmv2_fetch
    bmv2_prepare
    bmv2_build
}

ns3_configure() {
    step "ns3: register BMv2 for pkg-config (set_pkg_config_env.sh)"
    $SUDO install -d /usr/local/lib/pkgconfig
    $SUDO bash "$P4SIM/set_pkg_config_env.sh"
    # Ninja, unless the tree was configured with another generator before
    local gen="-G Ninja" cache=$NS3/cmake-cache/CMakeCache.txt mods=""
    if [ -f "$cache" ] && ! grep -q '^CMAKE_GENERATOR:INTERNAL=Ninja$' "$cache"; then gen=""; fi
    if [ "$NS3_SET_MODULES" = 1 ]; then
        step "ns3: configure (modules $NS3_MODULES, tests and examples of P4sim)"
        mods="--enable-modules='$NS3_MODULES' --filter-module-examples-and-tests=p4sim"
    else
        step "ns3: configure (keeps the modules of this tree; NS3_MODULES=... sets them)"
    fi
    run_logged ns3-configure bash -c "cd '$NS3' && ./ns3 configure $gen --enable-tests --enable-examples $mods"
    grep -E 'Modules configured to be built' -A4 "$LOGDIR/ns3-configure.log" | grep -vE '^\s*$' || true
}

ns3_build_deps() {
    step "ns3: build the modules P4sim depends on"
    # their library targets are lib<module> in older ns-3 releases (ns-3.39),
    # <module> in newer ones (ns-3.49)
    local prefix="" m targets="" c=$NS3/cmake-cache
    if grep -qs -e '^build libcore:' -e '^libcore:' "$c/build.ninja" "$c/Makefile"; then prefix=lib; fi
    for m in $NS3_DEP_MODULES; do targets="$targets $prefix$m"; done
    run_logged ns3-build-deps cmake --build "$NS3/cmake-cache" -j "$JOBS" --target $targets \
        || echo "(the full build below builds them)"
}

ns3_build() {
    step "ns3: build P4sim with its tests and examples"
    run_logged ns3-build bash -c "cd '$NS3' && ./ns3 build -j $JOBS"
    grep -E '^\[[0-9]+/[0-9]+\]' "$LOGDIR/ns3-build.log" | tail -n 1 || true
}

do_ns3() {
    ns3_fix
    # P4sim looks for the BMv2 libraries when ns-3 is configured
    ns3_configure
    ns3_build
}

do_test() {
    step "test: tools, one example, the test suites and examples of P4sim"
    cd "$NS3"
    local hint="" summary suites examples bad
    [ -z "$PYENV" ] || hint=" (the Python environment $PYENV needs the package thrift)"
    p4c --version | head -n 1
    simple_switch --version
    simple_switch_CLI --help > /dev/null || die "simple_switch_CLI does not run$hint"
    echo "simple_switch_CLI: OK"
    psa_switch_CLI --help > /dev/null || die "psa_switch_CLI does not run$hint"
    echo "psa_switch_CLI: OK"
    p4c --target bmv2 --arch v1model -o "$LOGDIR/p4c-check" \
        "$P4SIM/examples/p4src/p4_basic/p4_basic.p4" || die "p4c cannot compile p4_basic.p4"
    echo "p4c compile: OK"
    ./ns3 run --no-build p4-v1model-ipv4-forwarding > "$LOGDIR/example.txt" 2>&1 \
        || { tail -n 20 "$LOGDIR/example.txt"; die "the example p4-v1model-ipv4-forwarding failed"; }
    tail -n 5 "$LOGDIR/example.txt"
    if grep -q '^NS3_FILTER_MODULE_EXAMPLES_AND_TESTS:STRING=p4sim$' cmake-cache/CMakeCache.txt; then
        # only P4sim's tests and examples are built: test.py runs them all
        ./test.py --no-build 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$LOGDIR/test-py.txt" || true
        bad=$(grep -E '^\[[0-9]+/[0-9]+\] (FAIL|CRASH|VALGR)' "$LOGDIR/test-py.txt" || true)
        if [ -n "$bad" ]; then echo "$bad"; die "TESTS FAILED (log: $LOGDIR/test-py.txt)"; fi
        summary=$(grep -E '^[0-9]+ of [0-9]+ tests passed' "$LOGDIR/test-py.txt" | tail -n 1 || true)
        [ -n "$summary" ] || { tail -n 20 "$LOGDIR/test-py.txt"; die "test.py did not finish (log: $LOGDIR/test-py.txt)"; }
        echo "$summary"
        suites=$(grep -cE '^\[[0-9]+/[0-9]+\] PASS: TestSuite' "$LOGDIR/test-py.txt" || true)
        examples=$(grep -cE '^\[[0-9]+/[0-9]+\] PASS: Example' "$LOGDIR/test-py.txt" || true)
    else
        # more of ns-3 is configured: run only P4sim's suites and examples
        bash "$P4SIM/test/run-tests.sh" > "$LOGDIR/run-tests.txt" 2>&1 \
            || { grep FAIL "$LOGDIR/run-tests.txt" || tail -n 20 "$LOGDIR/run-tests.txt"; die "TESTS FAILED (log: $LOGDIR/run-tests.txt)"; }
        suites=$(grep -cE '^PASS -s ' "$LOGDIR/run-tests.txt" || true)
        examples=$(grep -cE '^PASS --example=' "$LOGDIR/run-tests.txt" || true)
        grep -E '^Skipped' "$LOGDIR/run-tests.txt" || true
    fi
    [ "$suites" -gt 0 ] && [ "$examples" -gt 0 ] || die "no test suite or example of P4sim ran"
    echo "P4sim test suites: $suites passed"
    echo "P4sim examples:    $examples passed"
}

# All steps, with the overlaps described at the top
do_all() {
    local t pid_fetch="" pid_prep=""
    t=$(date +%s)
    if bmv2_needed; then
        bmv2_new_src
        bmv2_fetch > "$LOGDIR/bmv2-fetch.log" 2>&1 &
        pid_fetch=$!
    fi
    do_apt
    [ -z "$pid_fetch" ] || wait_bg "$pid_fetch" bmv2-fetch
    ns3_fix
    TIMES+=("packages, p4c, downloads    $(( $(date +%s) - t )) s")

    t=$(date +%s)
    if [ -n "$pid_fetch" ]; then
        bmv2_prepare > "$LOGDIR/bmv2-prepare.log" 2>&1 &
        pid_prep=$!
    fi
    ns3_configure
    ns3_build_deps
    TIMES+=("ns-3 modules P4sim needs    $(( $(date +%s) - t )) s  (BMv2 configures meanwhile)")

    t=$(date +%s)
    if [ -n "$pid_prep" ]; then
        wait_bg "$pid_prep" bmv2-prepare
        bmv2_build
    else
        bmv2_note
    fi
    TIMES+=("BMv2                        $(( $(date +%s) - t )) s")

    t=$(date +%s)
    ns3_configure
    ns3_build
    TIMES+=("P4sim, its tests, examples  $(( $(date +%s) - t )) s")

    t=$(date +%s)
    do_test
    TIMES+=("tests                       $(( $(date +%s) - t )) s")
}

for s in "${STEPS[@]}"; do "do_$s"; done
step "done: ns-3 with P4sim in $NS3"
if [ ${#TIMES[@]} -gt 0 ]; then
    printf '  %s\n' "${TIMES[@]}"
    echo "  total                       $(( $(date +%s) - T0 )) s"
fi
echo "Next: cd $NS3 && ./ns3 run p4-hello, then contrib/p4sim/doc/getting-started.md"
echo "Logs: $LOGDIR"
