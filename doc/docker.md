# P4sim in Docker

The `Dockerfile` of this repository builds ns-3 with P4sim on BMv2 1.15.8 and
Thrift 0.16.0, with the P4 compiler p4c 1.2.5.19, on Ubuntu 24.04: the versions
the CI of P4sim tests. Only Docker is needed; nothing else is installed on the host.
To install P4sim on the host itself, see the quick installation in
[installation.md](installation.md#quick-installation).

## Build

```bash
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim
docker build -t p4sim .
```

The build takes about 6 minutes on 32 cores and half an hour on 8 cores; the image
takes about 2 GB. With little memory, limit the parallel jobs, for example
`--build-arg JOBS=4`. There is no prebuilt image.

The image uses ns-3.39; `--build-arg NS3_VERSION=ns-3.49` (or another release from
ns-3.40 on) builds it with that ns-3 instead.

- The image has the ns-3 modules that P4sim needs (and those that `netanim` needs),
  with tests and examples. BMv2 is built with optimisation, without PI.
- `--build-arg NS3_FILTER=p4sim` builds the tests and examples of P4sim only, not
  those of the other ns-3 modules, which halves the time of the ns-3 build. The CI
  builds the image this way.
- ns-3 is built in two steps, its modules first and then P4sim. After a change to
  P4sim, `docker build` takes the ns-3 modules from the build cache and compiles
  only P4sim.
- The debug information of the ns-3 build is removed, which saves several GB.
  `--build-arg DEBUG_INFO=yes` keeps it, for gdb.
- p4c comes from the official image `p4lang/p4c`: the `p4c` driver and the back
  ends for v1model, PSA and PNA.
- Without the `docker-buildx` package, Docker uses its older builder and prints a
  deprecation notice; the image is the same.

## Run

The image starts in the ns-3 folder, `/ns3`, with P4sim in `contrib/p4sim`:

```bash
docker run --rm -it p4sim                                        # a shell
docker run --rm p4sim ./ns3 run p4-v1model-ipv4-forwarding       # an example
docker run --rm p4sim contrib/p4sim/test/run-tests.sh            # all suites and examples
```

**Your own simulation.** Put its source files into a folder and mount the folder
under `scratch/`. The program is named after the file that has `main()`:

```bash
mkdir my-sims && cp my-sim.cc my-sims/
docker run --rm -v "$PWD/my-sims:/ns3/scratch/my-sims" p4sim ./ns3 run my-sim
```

**Output files** (pcap and trace files) are written to the working directory of the
program; set it to a mounted folder with `--cwd`. The files belong to root:

```bash
docker run --rm -v "$PWD/out:/out" p4sim ./ns3 run --cwd=/out p4-firewall
```

`--rm` throws the container away, so a scratch program is compiled again at every
run. To keep it, give the container a name instead
(`docker run -it --name p4sim-work ... p4sim`) and start it again with
`docker start -ai p4sim-work`.

## Compile P4 programs

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work p4sim \
    p4c-bm2-ss --p4v 16 -o my_program.json my_program.p4
```

`p4c-bm2-psa` compiles for PSA and `p4c-bm2-pna` for PNA; `p4c --target bmv2
--arch v1model` also works. `--user` makes the output belong to you.

## Notes

- Tested on x86-64 (amd64): Ubuntu 24.04 in WSL with Docker 29 and BuildKit, and
  Ubuntu 22.04 with Docker 29 and the older builder. The p4c image exists only for
  amd64.
- The GitHub workflow `.github/workflows/docker.yml` builds the image with
  `NS3_FILTER=p4sim` and runs `test/run-tests.sh` for every pull request. Pushes
  to `main` and a weekly run keep the layers in the GitHub Actions cache, so a
  pull request usually compiles only P4sim.
