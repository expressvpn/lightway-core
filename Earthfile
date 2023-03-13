VERSION 0.6
FROM --platform=linux/amd64 debian:bullseye-slim
WORKDIR /libhelium

debian-deps:
    RUN apt-get update
    RUN apt-get -y install build-essential git automake m4 libtool-bin cmake ruby-full python3-pip
    RUN gem install ceedling --no-user-install
    RUN pip3 install gcovr

libhelium-deps:
    FROM +debian-deps
    # Copy in the build configs
    COPY *.yml .
    COPY --dir wolfssl ./
    # Make the directory structure so that the config can be parsed
    # To improve caching we want to separate this out as the WolfSSL dependency
    # fetch and build are the slowest parts of the process.
    RUN mkdir -p src include test/support third_party/wolfssl
    # Build and fetch the dependencies
    RUN ceedling dependencies:make project:linux

build:
    FROM +libhelium-deps
    # Copy in the source and include files
    COPY --dir src include ./
    # Generate the release
    RUN ceedling release project:linux
    # Store the artifacts
    SAVE ARTIFACT build/release/libhelium.a ./libhelium.a AS LOCAL ./artifacts/libhelium.a
    SAVE ARTIFACT build/artifacts/compile_commands.json /compile_commands.json

test-copy:
    FROM +build
    COPY --dir test ./

test:
    FROM +test-copy
    # Run the tests
    RUN ceedling test project:linux

coverage:
    FROM +test-copy
    # Generate code coverage
    RUN ceedling gcov:all utils:gcov project:linux
    SAVE ARTIFACT build/artifacts/gcov/*.html AS LOCAL ./artifacts/code_coverage/html/
    SAVE ARTIFACT build/artifacts/gcov/*.xml AS LOCAL ./artifacts/code_coverage/xml/

compile-commands:
    FROM +build
    # Copy and write out the compile_commands.json for IDE code completion support
    COPY +build/compile_commands.json .
    SAVE ARTIFACT compile_commands.json AS LOCAL compile_commands.json

fuzz-deps:
    FROM +debian-deps
    RUN apt-get -y install wget
    RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
    RUN echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" | tee -a /etc/apt/sources.list.d/clang.list
    RUN echo "deb-src http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" | tee -a /etc/apt/sources.list.d/clang.list
    RUN apt-get update
    RUN apt-get install --no-install-recommends -y llvm-14 clang-14 clang-format-14 libclang-rt-14-dev
    RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100
    ENV CC=clang
    ENV CCLD=clang

fuzz:
    FROM +fuzz-deps
    # Copy in the build configs
    COPY *.yml .
    COPY --dir wolfssl ./
    # Make the directory structure so that the config can be parsed
    # To improve caching we want to separate this out as the WolfSSL dependency
    # fetch and build are the slowest parts of the process.
    RUN mkdir -p fuzz src include test/support third_party/wolfssl
    # Build and fetch the dependencies
    RUN ceedling dependencies:make project:fuzz_linux
    COPY --dir src include fuzz ./
    RUN ceedling release project:fuzz_linux
    RUN build/release/lightway-fuzz -max_len=1500 -runs=100000

all:
    BUILD +test
    BUILD +coverage
    BUILD +build

