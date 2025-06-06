VERSION 0.8
ARG distro=bookworm
FROM --platform=linux/amd64 debian:$distro-slim
WORKDIR /libhelium

debian-deps:
    RUN apt-get update
    RUN apt-get -y install --no-install-recommends build-essential git automake m4 libtool-bin cmake ruby-full python3-pip clang
    # Not including colrm seems to give an error when configuring wolfssl
    RUN apt-get -y install --no-install-recommends bsdmainutils
    RUN gem install ceedling --no-user-install
    RUN apt-get -y install --no-install-recommends gcovr

libhelium-deps:
    FROM +debian-deps
    # Copy in the build configs
    COPY --dir project.yml ceedling .
    # Make the directory structure so that the config can be parsed
    # To improve caching we want to separate this out as the WolfSSL dependency
    # fetch and build are the slowest parts of the process.
    RUN mkdir -p src/he include test/support third_party/wolfssl
    # Copy the patch files
    COPY --dir wolfssl ./
    # Build and fetch the dependencies
    RUN ceedling --mixin=linux_x64 clobber dependencies:make

build:
    FROM +libhelium-deps
    # Copy in the source and include files
    COPY --dir src include ./
    # Generate the release
    RUN ceedling --mixin=linux_x64 clobber release
    # Store the artifacts
    SAVE ARTIFACT build/release/libhelium.a ./libhelium.a AS LOCAL ./artifacts/libhelium.a
    SAVE ARTIFACT build/artifacts/compile_commands.json AS LOCAL ./artifacts/compile_commands.json

test-copy:
    FROM +build
    COPY --dir test ./

test:
    FROM +test-copy
    # Run the tests
    RUN ceedling --mixin=linux_x64 test
    SAVE ARTIFACT build/artifacts/compile_commands.json AS LOCAL ./artifacts/compile_commands.json

coverage:
    FROM +test-copy
    # Generate code coverage
    RUN ceedling --mixin=linux_x64 gcov:all
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

clean:
    LOCALLY
    RUN echo "Deleting build directories..."
    RUN rm -rf build third_party/builds

install-precommit:
    LOCALLY
    RUN echo "Installing pre-commit configs..."
    RUN python3 -m venv venv
	RUN venv/bin/python -m pip install pre-commit
	RUN venv/bin/pre-commit install

format:
    LOCALLY
    RUN git ls-files '**/*.c' '**/*.h' | grep -v -E '/mock_.*\.[ch]$$' | xargs clang-format -i -style=file

public-header:
    LOCALLY
    RUN echo "Generating public header..."
    RUN python3 -m venv venv
	RUN venv/bin/python -m pip install textx
	RUN cd python && PATH=../venv/bin:/usr/bin:$PATH ./make_public_header.sh && mv he.h ../public/he.h
