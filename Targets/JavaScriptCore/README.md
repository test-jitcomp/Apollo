# Target: JavaScriptCore

To build JavaScriptCore (jsc) for fuzzing:

1. Clone the WebKit mirror from https://github.com/WebKit/webkit
2. Run the fuzzbuild.sh script in the webkit root directory
3. FuzzBuild/Debug/bin/jsc will be the JavaScript shell for the fuzzer
