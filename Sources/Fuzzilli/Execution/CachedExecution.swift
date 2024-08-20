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

public struct CachedExecution: Execution {

    public let outcome: ExecutionOutcome
    public let stdout: String
    public let stderr: String
    public let fuzzout: String
    public let execTime: TimeInterval

    public init(for exec: Execution) {
        self.outcome = exec.outcome
        self.stdout = exec.stdout
        self.stderr = exec.stderr
        self.fuzzout = exec.fuzzout
        self.execTime = exec.execTime
    }
}
