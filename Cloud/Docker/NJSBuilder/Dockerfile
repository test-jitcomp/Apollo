FROM swift:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=bash

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get install -y git make

RUN useradd -m builder

RUN mkdir -p /home/builder/njs
WORKDIR /home/builder/njs

# Docker will attempt to cache the output of every step. That's fine (and useful to speed things up, e.g. by avoiding
# the need to download the entire source repository again every time!). However, whenever the following ARG is changed
# (i.e. we are building a new version of the engine), a cache miss occurs (because the build context changed) and all
# steps from here on are rerun. That, however, means we might be operating on an old checkout of the source code from
# the cache, and so we update it again before checking out the requested revision.
ARG rev=master

# Upload scripts and artifacts for building njs for fuzzilli
ADD mod mod
ADD setup.sh setup.sh
ADD fuzzbuild.sh fuzzbuild.sh

# Setup njs for fuzzilli
RUN ./setup.sh

# Start building!
RUN ./fuzzbuild.sh
