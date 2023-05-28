FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang cmake pkg-config libeigen3-dev libpng-dev libboost-all-dev

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_libfive_opcode_enum.cpp -fsanitize=fuzzer,address -I /install/include/ -std=c++17 -I /usr/include/eigen3/ /install/lib/libfive.so -o /fuzz

FROM ubuntu:22.04 as package

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpng-dev

COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_libfive_opcode_enum
ENV LD_LIBRARY_PATH=/install/lib/

