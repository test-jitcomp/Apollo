// Copyright 2024 Cong Li (congli@smail.nju.edu.cn, cong.li@inf.ethz.ch)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

public class JavaScriptCompatLifter: JavaScriptLifter {
    public static let globalThisName = "__compat_global__";
    public static let printFuncName = "__compat_out__";
    public static let chksumContainerName = "__compat_checksum__";
    public static let chksumIndexInContainer = 0;
    public static let chksumCounterIndexInContainer = 1;

    public static let codePrefix = """
    (function(\(globalThisName)){
    //
    // Define a print function as not all engines defined console.
    //
    const \(printFuncName) = (
       (\(globalThisName))['console'] &&
       (\(globalThisName))['console'].log
    ) || (\(globalThisName))['print'];

    //
    // Define a checksum for the Javascript program. The generated code
    // has the flexibility to operate on it. In below cotainer (an array):
    //
    // * We put the chksum value at the 0th position.
    // * For the 1st position, we put a map which serves as a chksum update
    // counter. The counter associates the number of chksum updates with
    // each subroutine. We design such a map as, the implicit type conventions
    // (which often cause implicit subroutine calls for example toString(),
    // toValue(), etc.), when executed too much (due to Fuzzilli-generated
    // arbitratry code), may lead to quite unstable chksum updates.
    // This further leads us to capturing a quantities of false-positive
    // miscompilations. We design this dict to restrict the number
    // of chksum updates for each subroutine.
    //
    const \(chksumContainerName) = [0xAB0110, {}];

    //
    // Wrap all generated code by a try-finally block to ensure
    // the checksum are always being printed.
    //
    try {

    //
    // Generated code starts here
    //
    """

    public static let codeSuffix = """
    //
    // Generated code ends here
    //

    } finally {
        //
        // Print the checksum as an indicator of the program.
        // This may be helpful for differential testing.
        //
        // WARNING:
        // - Do NOT use template strings which Duktape does not support.
        //   See: https://github.com/svaarala/duktape/issues/273
        //
        \(printFuncName)("Checksum: " + \(chksumContainerName)[\(chksumIndexInContainer)]);
    }
    })(globalThis || global);
    """

    public convenience init(prefix: String = "", suffix: String = "", ecmaVersion: ECMAScriptVersion) {
        self.init(
            prefix: JavaScriptCompatLifter.codePrefix + prefix,
            suffix: suffix + JavaScriptCompatLifter.codeSuffix,
            optimOptions: .allowAllOptimizations.subtracting(.allowOptimizingReassign), // We conservatively disable allow inlining operations
            ecmaVersion: ecmaVersion
        )
    }

    private override init(
        prefix: String = "",
        suffix: String = "",
        optimOptions: JavaScriptOptimOptions = .allowAllOptimizations,
        ecmaVersion: ECMAScriptVersion
    ) {
        super.init(
            prefix: prefix,
            suffix: suffix,
            optimOptions: optimOptions,
            ecmaVersion: ecmaVersion
        )
    }
}
