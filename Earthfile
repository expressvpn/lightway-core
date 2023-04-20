VERSION 0.7
FROM --platform=linux/amd64 debian:bullseye-slim
WORKDIR /libhelium

debian-deps:
    RUN apt-get update
    RUN apt-get -y install --no-install-recommends build-essential git automake m4 libtool-bin cmake ruby-full python3-pip
    # Not including colrm seems to give an error when configuring wolfssl
    RUN apt-get -y install --no-install-recommends bsdmainutils
    RUN gem install ceedling --no-user-install
    RUN pip3 install gcovr

libhelium-deps:
    FROM +debian-deps
    # Copy in the build configs
    COPY *.yml .
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


all:
    BUILD +test
    BUILD +coverage
    BUILD +build

