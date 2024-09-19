// Copyright 2020 Google LLC
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

public class FuzzEngine: ComponentBase {
    private var postProcessor: FuzzingPostProcessor? = nil

    override init(name: String) {
        super.init(name: name)
    }

    // Install a post-processor that is executed for every generated program and can modify it (by returning a different program).
    public func registerPostProcessor(_ postProcessor: FuzzingPostProcessor) {
        assert(self.postProcessor == nil)
        self.postProcessor = postProcessor
    }

    // Performs a single round of fuzzing using the engine.
    public func fuzzOne(_ group: DispatchGroup) {
        fatalError("Must be implemented by child classes")
    }

    final func execute(_ program: Program, withTimeout timeout: UInt32? = nil) -> ExecutionOutcome {
        return self.execute0(program, withTimeout: timeout, withCaching: false).outcome
    }

    final func execute0(_ program: Program, withTimeout timeout: UInt32? = nil, withCaching: Bool = false) -> Execution {
        let program = postProcessor?.process(program, for: fuzzer) ?? program

        fuzzer.dispatchEvent(fuzzer.events.ProgramGenerated, data: program)

        let execution = fuzzer.execute(program, withTimeout: timeout, purpose: .fuzzing, withCaching: withCaching)

        switch execution.outcome {
            case .crashed(let termsig):
                fuzzer.processCrash(program, withSignal: termsig, withStderr: execution.stderr, withStdout: execution.stdout, origin: .local, withExectime: execution.execTime)
                program.contributors.generatedCrashingSample()

            case .succeeded:
                fuzzer.dispatchEvent(fuzzer.events.ValidProgramFound, data: program)
                var isInteresting = false
                if let aspects = fuzzer.evaluator.evaluate(execution) {
                    if fuzzer.config.enableInspection {
                        program.comments.add("Program may be interesting due to \(aspects)", at: .footer)
                        program.comments.add("RUNNER ARGS: \(fuzzer.runner.processArguments.joined(separator: " "))", at: .header)
                    }
                    isInteresting = fuzzer.processMaybeInteresting(program, havingAspects: aspects, origin: .local)
                }

                if isInteresting {
                    program.contributors.generatedInterestingSample()
                } else {
                    program.contributors.generatedValidSample()
                }

            case .failed(_):
                if fuzzer.config.enableDiagnostics {
                    program.comments.add("Stdout:\n" + execution.stdout, at: .footer)
                }
                fuzzer.dispatchEvent(fuzzer.events.InvalidProgramFound, data: program)
                program.contributors.generatedInvalidSample()

            case .timedOut:
                fuzzer.dispatchEvent(fuzzer.events.TimeOutFound, data: program)
                program.contributors.generatedTimeOutSample()
        }

        if fuzzer.config.enableDiagnostics {
            // Ensure deterministic execution behaviour. This can for example help detect and debug REPRL issues.
            ensureDeterministicExecutionOutcomeForDiagnostic(of: program)
        }

        return execution
    }

    private final func ensureDeterministicExecutionOutcomeForDiagnostic(of program: Program) {
        let execution1 = fuzzer.execute(program, purpose: .other)
        let stdout1 = execution1.stdout, stderr1 = execution1.stderr
        let execution2 = fuzzer.execute(program, purpose: .other)
        switch (execution1.outcome, execution2.outcome) {
        case (.succeeded, .failed(_)),
             (.failed(_), .succeeded):
            let stdout2 = execution2.stdout, stderr2 = execution2.stderr
            logger.warning("""
                Non-deterministic execution detected for program
                \(fuzzer.lifter.lift(program))
                // Stdout of first execution
                \(stdout1)
                // Stderr of first execution
                \(stderr1)
                // Stdout of second execution
                \(stdout2)
                // Stderr of second execution
                \(stderr2)
                """)
        default:
            break
        }
    }

    /// Checks if the given program is deterministic and perhaps suitable for finding miscompilations bugs.
    func mayBeDeterministicExecutionStdout(_ program: Program, n: Int) -> Bool {
        /// Run a program multiple times to check if the program's execution is deterministic.
        ///
        /// This is often a required action before we perform like JoN mutations or other actions pertaining to
        /// finding miscompilations. This is because the programs generated by Fuzzilli are too random to like
        /// cause the JavaScript engine stack overflow, rendering the program output quite flaky, even through
        /// the flaky program is not a bug trigger :-).
        func isExecStdoutDeterm() -> Bool {
            // Let run it for n times and check if the execution is deterministic
            let ref = fuzzer.execute(program, purpose: .other, withCaching: true)
            if ref.outcome != .succeeded {
                return false  // We accidentally picked an interesting program
            }

            // Run for a couple of rounds to check if it is deterministic
            for _  in 1..<n {
                let cur = fuzzer.execute(program, purpose: .other, withCaching: true)
                if cur.outcome != .succeeded {
                    return false  // Interesting flaky tests: the outcome changed; not deterministic
                } else if cur.stdout != ref.stdout {
                    return false  // The stdout changed; it's not deterministic but might not be a bug
                    // as we often generate tests that causes the JavaScript engine stack overflow.
                }
            }

            return true  // We assume the stdout are deterministic
        }

        return isExecStdoutDeterm()
    }
}
