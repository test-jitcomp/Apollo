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
    public static let codePrefix = """
    (function(__compat_global__){
        //
        // Not all engines defined console.
        //
        const __compat_out__ = (
           (__compat_global__)['console'] &&
           (__compat_global__)['console'].log
        ) || (__compat_global__)['print'];

    """

    public static let codeSuffix = """

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
