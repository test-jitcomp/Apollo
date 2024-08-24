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
    // Define a checksum for the Javascript program.
    // The code have the flexibility to operate on it.
    //
    const \(chksumContainerName) = [0xAB0110];

    //
    // Wrap all generated code by a try-finally block to ensure
    // the checksum are always being printed.
    //
    try {

    """

    public static let codeSuffix = """

    } finally {
        //
        // Print the checksum as an indicator of the program.
        // This may be helpful for differential testing.
        //
        \(printFuncName)(`Checksum: ${\(chksumContainerName)[\(chksumIndexInContainer)]}`);
    }
    })(globalThis || global);
    """

    public override init(prefix: String = "", suffix: String = "", ecmaVersion: ECMAScriptVersion) {
        super.init(
            prefix: JavaScriptCompatLifter.codePrefix + prefix,
            suffix: suffix + JavaScriptCompatLifter.codeSuffix,
            ecmaVersion: ecmaVersion
        )
    }
}
