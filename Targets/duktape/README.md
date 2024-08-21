# Target: duktape

To build duktape for fuzzing:

1. Clone the duktape repository from https://github.com/svaarala/duktape
2. Apply Patches/\*. The patches should apply cleanly to the git revision specified in [./REVISION](./REVISION)
3. Run `make build/duk-fuzzilli`

The executable will be named `duk-fuzzilli`, in the duktape directory.
