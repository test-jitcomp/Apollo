#!/bin/bash

set -e

cd $(dirname $0)
FUZZILLI_ROOT=../../..

# Setup build context
REV=$(cat $FUZZILLI_ROOT/Targets/duktape/REVISION)
cp -R $FUZZILLI_ROOT/Targets/duktape/Patches .

# Fetch the source code, get the current master commit, and compile the engine
docker build --build-arg rev=$REV -t duktape_builder .

# Copy build products
mkdir -p out
docker create --name temp_container duktape_builder
docker cp temp_container:/home/builder/duktape/build/duk-fuzzilli out/duk-fuzzilli
docker rm temp_container

# Nothing extra to clean up!
