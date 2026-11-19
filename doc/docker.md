# P4sim in Docker

The `Dockerfile` of this repository builds ns-3.39 with P4sim on BMv2 1.15.8 and
Thrift 0.16.0 (Ubuntu 24.04), the versions P4sim is tested with. Only Docker is
needed; nothing else is installed on the host.

## Build

```bash
git clone https://github.com/HapCommSys/p4sim.git
cd p4sim
docker build -t p4sim .
```

The build takes about 25 minutes on 8 cores, and the image takes about 7 GB, mostly
for the ns-3 build (half of a native installation). With little memory, limit the
parallel jobs, for example `--build-arg JOBS=4`. There is no prebuilt image.

The image contains the ns-3 modules that P4sim needs, with tests and examples.
BMv2 is built with optimisation, without PI.

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

The image has no P4 compiler. Use the image of p4c, in the version P4sim is tested
with:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work p4lang/p4c:1.2.5.19 \
    p4c-bm2-ss --p4v 16 -o my_program.json my_program.p4
```

`p4c-bm2-psa` compiles for PSA and `p4c-bm2-pna` for PNA.

## Notes

- Tested on x86-64 (amd64). The p4c image exists only for amd64.
- The GitHub workflow `.github/workflows/docker.yml` builds the image and runs
  `test/run-tests.sh` for every pull request.
