FROM swift:5.10.1

ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=bash

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get install -y git make clang bc curl python3 python3-pip nodejs npm

# Update NodeJS and NPM to the latest versions
RUN npm install -g n
RUN n latest
RUN npm install -g npm

# Dependency of the duktape build process
RUN pip3 install pyyaml

RUN useradd -m builder

RUN git clone https://github.com/svaarala/duktape.git /home/builder/duktape
WORKDIR /home/builder/duktape

# The hash of the most recent commit is passed in from the build script, to ensure proper caching behavior
ARG rev

# Update system packages first
RUN apt-get -y update && apt-get -y upgrade

# Fetch latest source code and checkout requested source revision
RUN git pull && git checkout $rev

# Apply patches to the specified revision
ADD Patches Patches
RUN for i in `ls Patches`; do patch -p1 < Patches/$i; done

# Make normally to pull down NodeJS deps
RUN make

# Assume that the current master branch maintains duk-fuzzilli
# No need to patch, as the fuzz target is maintained in the duktape repo
# Start building!
RUN make build/duk-fuzzilli
