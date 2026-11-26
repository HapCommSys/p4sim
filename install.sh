#!/bin/bash
# Quick installation of P4sim on Ubuntu 24.04 or 26.04: installs what P4sim
# needs, then builds and tests ns-3 with P4sim. About 6 minutes on 16 cores.
#
#   Ubuntu packages  compilers, CMake, Ninja, ccache, Thrift and the libraries
#                    of BMv2 and P4sim
#   p4c              the prebuilt package of p4lang (repository home:p4lang on
#                    download.opensuse.org)
#   BMv2 1.15.8      built from source, because P4sim compiles against its
#                    headers and Thrift service libraries: shared libraries and
#                    the targets simple_switch and psa_switch, in /usr/local
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
#                          ns-3 are busy
#
# Settings (environment variables):
#   JOBS          parallel build jobs (default: one per CPU)
#   NS3_MODULES   ns-3 modules to build (default "p4sim;nix-vector-routing",
#                 plus the modules they depend on)
#   BMV2_REBUILD  1: build and install BMv2 even if another BMv2 is installed
#   LOGDIR        log files (default /tmp/p4sim-install-<user id>)

set -euo pipefail
JOBS=${JOBS:-$(nproc)}
NS3_MODULES=${NS3_MODULES:-p4sim;nix-vector-routing}
BMV2_REBUILD=${BMV2_REBUILD:-0}
LOGDIR=${LOGDIR:-/tmp/p4sim-install-$(id -u)}
BMV2_VERSION=1.15.8
BMV2_RECIPE="shared-only,simple_switch+psa_switch"   # a change rebuilds BMv2
BMV2_SRC=${TMPDIR:-/tmp}/p4sim-bmv2-$(id -u)
BMV2_STAMP=/usr/local/share/p4sim/bmv2.stamp
# ns-3 modules P4sim depends on: built while BMv2 configures
NS3_DEP_MODULES="nix-vector-routing csma point-to-point applications bridge"
P4SIM=$(cd "$(dirname "$0")" && pwd)
NS3=$(cd "$P4SIM/../.." && pwd)
APT="env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o Acquire::Retries=5 -o Dpkg::Use-Pty=0 --no-install-recommends"

die() { echo "install.sh: $*" >&2; exit 1; }
[ -x "$NS3/ns3" ] && [ "$(basename "$(dirname "$P4SIM")")" = contrib ] \
    || die "run me from an ns-3 tree, as <ns-3>/contrib/p4sim/install.sh (see the top of this file)"

# WSL appends the Windows PATH (/mnt/c/...). ./ns3 configure stores PATH and
# test.py adds it to LD_LIBRARY_PATH, which makes every start of a runtime CLI
# slow; leave it out.
if grep -qi microsoft /proc/version 2>/dev/null; then
    PATH=$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '^/mnt/' | paste -sd: -)
    export PATH
fi

mkdir -p "$LOGDIR"
LOG=$LOGDIR/install.log
exec > >(tee -a "$LOG") 2>&1

if [ "$(id -u)" = 0 ]; then
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
    local key=/etc/apt/keyrings/home-p4lang.gpg
    if ! command -v curl >/dev/null || ! command -v gpg >/dev/null; then
        $SUDO apt-get -q update
        $SUDO $APT install ca-certificates curl gpg
    fi
    $SUDO install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "$repo/Release.key" | gpg --dearmor | $SUDO tee "$key" > /dev/null
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
    python3 - "$NS3/ns3" <<'PY'
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
# 0 if BMv2 must be built: not installed by this script in this version, and no
# other BMv2 installed (or BMV2_REBUILD=1)
bmv2_needed() {
    if [ "$(cat "$BMV2_STAMP" 2>/dev/null)" = "$(bmv2_want)" ] &&
       python3 -c 'import runtime_CLI, sswitch_runtime, pswitch_runtime' 2>/dev/null; then
        return 1
    fi
    if [ ! -e "$BMV2_STAMP" ] && [ "$BMV2_REBUILD" != 1 ] && command -v simple_switch > /dev/null; then
        return 1
    fi
    return 0
}
bmv2_note() {
    if [ -e "$BMV2_STAMP" ]; then
        step "bmv2: already installed ($(cat "$BMV2_STAMP"))"
    else
        step "bmv2: using the installed BMv2, $(command -v simple_switch): $(simple_switch --version)"
        echo "(BMV2_REBUILD=1 replaces it with BMv2 $BMV2_VERSION)"
    fi
}

bmv2_fetch() {
    step "bmv2: download $BMV2_VERSION"
    $SUDO rm -rf "$BMV2_SRC"
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
    pydir=$(python3 -c 'import site; print(site.getsitepackages()[0])')
    cd "$BMV2_SRC"
    run_logged bmv2-make make -s -j"$JOBS"
    # headers of an earlier BMv2 in /usr/local
    $SUDO rm -rf /usr/local/include/bm
    run_logged bmv2-install $SUDO make -s install-strip pythondir="$pydir" pyexecdir="$pydir"
    $SUDO ldconfig
    cd "$NS3"
    $SUDO rm -rf "$BMV2_SRC"
    $SUDO install -d "$(dirname "$BMV2_STAMP")"
    bmv2_want | $SUDO tee "$BMV2_STAMP" > /dev/null
    simple_switch --version
    python3 -c 'import runtime_CLI, sswitch_runtime, pswitch_runtime' && echo "BMv2 Python modules: OK"
}

do_bmv2() {
    if ! bmv2_needed; then bmv2_note; return; fi
    bmv2_fetch
    bmv2_prepare
    bmv2_build
}

ns3_configure() {
    step "ns3: register BMv2 for pkg-config (set_pkg_config_env.sh)"
    $SUDO install -d /usr/local/lib/pkgconfig
    $SUDO bash "$P4SIM/set_pkg_config_env.sh"
    step "ns3: configure (modules $NS3_MODULES, tests and examples of P4sim)"
    # Ninja, unless the tree was configured with another generator before
    local gen="-G Ninja" cache=$NS3/cmake-cache/CMakeCache.txt
    if [ -f "$cache" ] && ! grep -q '^CMAKE_GENERATOR:INTERNAL=Ninja$' "$cache"; then gen=""; fi
    run_logged ns3-configure bash -c "cd '$NS3' && ./ns3 configure $gen --enable-tests --enable-examples \
        --enable-modules='$NS3_MODULES' --filter-module-examples-and-tests=p4sim"
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
    p4c --version | head -n 1
    simple_switch --version
    simple_switch_CLI --help > /dev/null && echo "simple_switch_CLI: OK"
    psa_switch_CLI --help > /dev/null && echo "psa_switch_CLI: OK"
    p4c --target bmv2 --arch v1model -o "$LOGDIR/p4c-check" \
        "$P4SIM/examples/p4src/p4_basic/p4_basic.p4" && echo "p4c compile: OK"
    ./ns3 run --no-build p4-v1model-ipv4-forwarding 2>&1 | tail -n 5
    ./test.py --no-build 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$LOGDIR/test-py.txt" || true
    grep -E '^[0-9]+ of [0-9]+ tests passed' "$LOGDIR/test-py.txt" | tail -n 1 || true
    local bad
    bad=$(grep -E '^\[[0-9]+/[0-9]+\] (FAIL|CRASH|VALGR)' "$LOGDIR/test-py.txt" || true)
    if [ -n "$bad" ]; then echo "$bad"; die "TESTS FAILED (log: $LOGDIR/test-py.txt)"; fi
    echo "P4sim test suites: $(grep -cE '^\[[0-9]+/[0-9]+\] PASS: TestSuite' "$LOGDIR/test-py.txt") passed"
    echo "P4sim examples:    $(grep -cE '^\[[0-9]+/[0-9]+\] PASS: Example' "$LOGDIR/test-py.txt") passed"
}

# All steps, with the overlaps described at the top
do_all() {
    local t pid_fetch="" pid_prep=""
    t=$(date +%s)
    if bmv2_needed; then
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

for s in "${@:-all}"; do
    case "$s" in
        all | apt | bmv2 | ns3 | test) "do_$s" ;;
        *) die "unknown step $s (steps: apt bmv2 ns3 test)" ;;
    esac
done
step "done: ns-3 with P4sim in $NS3"
if [ ${#TIMES[@]} -gt 0 ]; then
    printf '  %s\n' "${TIMES[@]}"
    echo "  total                       $(( $(date +%s) - T0 )) s"
fi
echo "Next: cd $NS3 && ./ns3 run p4-v1model-ipv4-forwarding"
echo "Logs: $LOGDIR"
