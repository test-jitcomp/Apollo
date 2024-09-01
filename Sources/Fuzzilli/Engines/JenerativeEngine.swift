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

// TODO: Perhaps moving to ProgramTemplates.java
let JProgramTemplates: [ProgramTemplate] = [
    ProgramTemplate("InstrGen:15i") { b in
        b.buildValues(5)
        b.build(n: 10, by: .generating)
    },

    ProgramTemplate("SubrtGen:3s10i") { b in
        b.buildValues(5)
        for i in 1...3 {
            withEqualProbability({
                b.buildPlainFunction(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }, {
                b.buildArrowFunction(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }, {
                b.buildConstructor(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            })
            b.build(n: 5, by: .generating)
        }
    },

    ProgramTemplate("SubrtPlainCallGen:3s10i3c") { b in
        b.buildValues(5)
        var subrts = [Variable]()
        for i in 1...3 {
            let j = subrts.isEmpty ? 0 : Int.random(in: 1...subrts.count)
            subrts.append(withEqualProbability({
                b.buildPlainFunction(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }, {
                b.buildArrowFunction(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }, {
                b.buildConstructor(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }))
            b.build(n: 2, by: .generating)
            b.callFunction(subrts[j], withArgs: b.randomArguments(
                forCalling: subrts[j]
            ))
            b.build(n: 2, by: .generating)
        }
    },

    ProgramTemplate("SubrtJITCallGen:3s10i3c") { b in
        b.buildValues(5)
        var subrts = [Variable]()
        for i in 1...3 {
            let j = subrts.isEmpty ? 0 : Int.random(in: 1...subrts.count)
            subrts.append(withEqualProbability({
                b.buildPlainFunction(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }, {
                b.buildArrowFunction(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }, {
                b.buildConstructor(with: .parameters(n: i)) { _ in
                    b.build(n: 10, by: .generating)
                }
            }))
            b.build(n: 2, by: .generating)
            withEqualProbability({
                b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
                    b.build(n: 1, by: .generating)
                    b.callFunction(subrts[j], withArgs: b.randomArguments(
                        forCalling: subrts[j]
                    ))
                    b.build(n: 1, by: .generating)
                }
            }, {
                b.callFunction(subrts[j], withArgs: b.randomArguments(
                    forCalling: subrts[j]
                ))
            })
            b.build(n: 2, by: .generating)
        }
    }
]


/// A generative engine working for JIT-related engines and mutators for example JITMutEngine and JoNEngine.
///
/// Different from GenerativeEngine, this engine focus more on generating subroutine that are mutable by them.
class JenerativeEngine: FuzzEngine {
    /// Number of samples to generate in one round.
    private let numConsecutiveJenerations: Int

    /// Templates for us
    private let templates = WeightedList<ProgramTemplate>([
        "InstrGen:15i":                  6,
        "SubrtGen:3s10i":                5,
        "SubrtPlainCallGen:3s10i3c":     4,
        "SubrtJITCallGen:3s10i3c":       1,
    ].map({ key, val in
        (JProgramTemplates.first(where: { $0.name == key })!, val)
    }))

    public init(numConsecutiveJenerations: Int) {
        self.numConsecutiveJenerations = numConsecutiveJenerations
        super.init(name: "JenerativeEngine")
    }

    /// Perform one round of fuzzing: simply generate a new program and execute it
    public override func fuzzOne(_ group: DispatchGroup) {
        for _ in 0..<self.numConsecutiveJenerations {
            let b = fuzzer.makeBuilder()
            self.templates.randomElement().generate(in: b)
            let program = b.finalize()
            let _ = execute(program)
        }
    }
}
