# P4sim in a container: ns-3.39 with P4sim, BMv2 1.15.8 and Thrift 0.16.0 on
# Ubuntu 24.04, the versions P4sim is tested with. The P4 compiler is not
# included: compile P4 programs with the image p4lang/p4c (see doc/docker.md).
#
#   docker build -t p4sim .
#   docker run --rm -it p4sim ./ns3 run p4-v1model-ipv4-forwarding

FROM ubuntu:24.04

ARG THRIFT_VERSION=0.16.0
ARG BMV2_VERSION=1.15.8
ARG NS3_VERSION=ns-3.39
# Parallel build jobs; empty means one per CPU
ARG JOBS=

ENV DEBIAN_FRONTEND=noninteractive

# Build tools and the libraries that Thrift, BMv2 and ns-3 need
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake bison build-essential ca-certificates cmake flex git \
        libboost-dev libboost-filesystem-dev libboost-program-options-dev \
        libboost-system-dev libboost-thread-dev libevent-dev libffi-dev libgmp-dev \
        libjsoncpp-dev libnanomsg-dev libpcap-dev libprotobuf-dev libreadline-dev \
        libssl-dev libtool libtool-bin libxxhash-dev pkg-config protobuf-compiler \
        python-is-python3 python3 python3-dev python3-pip python3-six \
    && rm -rf /var/lib/apt/lists/*

# Thrift, for the runtime CLIs of BMv2 (C++ library and Python package)
RUN git clone --depth 1 -b v${THRIFT_VERSION} https://github.com/apache/thrift.git /tmp/thrift \
    && cd /tmp/thrift \
    && ./bootstrap.sh \
    && ./configure --with-cpp=yes --with-python=yes --enable-tests=no --enable-tutorial=no \
        --with-as3=no --with-c_glib=no --with-cl=no --with-csharp=no --with-d=no \
        --with-dart=no --with-dotnetcore=no --with-erlang=no --with-go=no \
        --with-haskell=no --with-haxe=no --with-java=no --with-js=no --with-lua=no \
        --with-netstd=no --with-nodejs=no --with-nodets=no --with-perl=no \
        --with-php=no --with-qt5=no --with-ruby=no --with-rs=no --with-swift=no \
    && make -j${JOBS:-$(nproc)} \
    && make install \
    && pip3 install --no-cache-dir --break-system-packages ./lib/py \
    && ldconfig \
    && rm -rf /tmp/thrift

# BMv2 with its Thrift services (simple_switch, psa_switch, pna_nic)
RUN git clone --depth 1 -b ${BMV2_VERSION} https://github.com/p4lang/behavioral-model.git /tmp/bmv2 \
    && cd /tmp/bmv2 \
    && ./autogen.sh \
    && ./configure --with-thrift \
    && make -j${JOBS:-$(nproc)} \
    && make install-strip \
    && ldconfig \
    && rm -rf /tmp/bmv2

# ns-3 with P4sim from this repository
RUN git clone --depth 1 -b ${NS3_VERSION} https://github.com/nsnam/ns-3-dev-git.git /ns3
COPY . /ns3/contrib/p4sim
WORKDIR /ns3
RUN bash contrib/p4sim/set_pkg_config_env.sh \
    && ./ns3 configure --enable-tests --enable-examples \
        --enable-modules="p4sim;netanim;nix-vector-routing" \
    && ./ns3 build -j ${JOBS:-$(nproc)}

CMD ["bash"]
