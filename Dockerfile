# Base image
FROM ubuntu:22.04

# Update package repository and install dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    git \
    g++ \
    build-essential \
    autoconf \
    libtool \
    pkg-config \
    libgflags-dev \
    libgtest-dev \
    clang \
    libc++-dev \
    libgrpc++-dev \
    libgrpc-dev \
    protobuf-compiler \
    protobuf-compiler-grpc \
    openssl \
    cmake \
    libssl-dev \
    libleveldb-dev \
    libboost-all-dev \
    libsodium-dev \
    wget \
    git \
    ccache \
    zlib1g-dev \
    libsnappy-dev \
    liblz4-dev \
    libzstd-dev && \
    apt-get clean


ENV CC="ccache gcc"
ENV CXX="ccache g++"

# Install RocksDB
RUN git clone --branch v8.0.0 https://github.com/facebook/rocksdb.git && \
    cd rocksdb && \
    make shared_lib && \
    make install-shared && \
    ldconfig && \
    cd .. && rm -rf rocksdb

# Install WasmEdge
RUN wget https://github.com/WasmEdge/WasmEdge/releases/download/0.11.2/WasmEdge-0.11.2-manylinux2014_x86_64.tar.gz && \
    tar -xvzf WasmEdge-0.11.2-manylinux2014_x86_64.tar.gz && \
    cp -r WasmEdge-0.11.2-Linux/include/wasmedge /usr/local/include/ && \
    cp WasmEdge-0.11.2-Linux/lib64/libwasmedge.so /usr/local/lib/ && \
    cp WasmEdge-0.11.2-Linux/lib64/libwasmedge.so.0 /usr/local/lib/

ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

RUN git clone --recursive https://github.com/WebAssembly/wabt && \
    cd wabt && \
    git submodule update --init

# Build WABT
RUN cd wabt && \
    mkdir build && \
    cd build && \
    cmake .. && \
    cmake --build .

# Clean up to reduce image size
# RUN rm -rf /var/lib/apt/lists/* wabt

# Create the target directory in the root's home directory
RUN mkdir -p Downloads/wabt/build/


# Copy the wasm2wat binary to the desired location
RUN cp wabt/build/wasm2wat Downloads/wabt/build/wasm2wat

# Set the path to prioritize ccache
ENV PATH="/usr/lib/ccache:$PATH"

# Directory for ccache to store its cache
RUN mkdir -p /data
RUN mkdir -p /data/config
RUN mkdir -p /data/ccache
RUN mkdir -p /data/blockchain
RUN mkdir -p /data/logs
RUN mkdir -p /data/reorgs
RUN mkdir -p /data/copy
ENV CCACHE_DIR /data/ccache


# Open ports
EXPOSE 50051
EXPOSE 50052
EXPOSE 50053

# Copy files
COPY . .

#make proto and grpc files
RUN cd /z_validator/proto && \
    protoc \
    --grpc_out=/z_validator/headers \
    --cpp_out=/z_validator/headers *.proto \
    --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` \
    --experimental_allow_proto3_optional

# Build the validator with AddressSanitizer
RUN cd /z_validator && \
    mkdir build && \
    cd build && \
    cmake ../.. && \
    make -j$(nproc)

# Copy the zera-validator binary to PATH
RUN cp z_validator/build/zera-validator /usr/local/bin/


# Run the validator
#CMD ["sh", "-c", "while true; do sleep 1000; done"]
CMD ["zera-validator"]