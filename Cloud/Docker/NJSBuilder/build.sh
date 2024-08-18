#!/bin/bash

set -e

cd $(dirname $0)
FUZZILLI_ROOT=../../..

# Setup build context
REV=$(cat $FUZZILLI_ROOT/Targets/njs/REVISION)
cp -R $FUZZILLI_ROOT/Targets/njs/mod .
cp $FUZZILLI_ROOT/Targets/njs/setup.sh .
cp $FUZZILLI_ROOT/Targets/njs/fuzzbuild.sh .

# Fetch the source code, apply patches, and compile the engine
docker build --build-arg rev=$REV -t njs_builder .

# Copy build products
mkdir -p out
docker create --name temp_container njs_builder
docker cp temp_container:/home/builder/njs/njs/build/njs_fuzzilli out/njs_fuzzilli
docker rm temp_container

# Clean up
rm -r mod setup.sh fuzzbuild.sh
