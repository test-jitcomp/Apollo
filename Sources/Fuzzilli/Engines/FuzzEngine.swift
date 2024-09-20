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

        /// Check if there're any infinite recursions that never stop, which will cause stack's draining out.
        ///
        /// Even though we have disabled the generation of recursive function calls by default, this option can
        /// still be enabled by users, and most importantly, our minimizer may minimize a program to contain such
        /// unlimited recursive calls. We deem all programs with such "features" as undeterministic programs as
        /// different JavaScript engines have a different stack size, leading to different number of executions for a
        /// recursive function call. Our rules for such checks are simple: if an recursive call is applied prior to a
        /// return instruction, we aggressively treat this recursive call as an unlimited, infinite call.
        func containsUnlimitedRecursions() -> Bool {
            func foundUnlimitedRecursionIn(_ subrt: BlockGroup, as isRecursion: (Instruction) -> Bool) -> Bool {
                var ret: Instruction? = nil
                var index = subrt.head + 1
                while index < subrt.tail {
                    let instr = program.code[index]
                    if instr.op is BeginAnySubroutine { // We skip all sub subroutines
                        index = program.code.findBlockEnd(head: index) + 1
                    } else if instr.op is Return { // We found a return instruction
                        ret = instr
                        index += 1
                    } else if ret == nil && isRecursion(instr) {
                        return true  // No returns found, but the recursion condition satisfies
                    } else {
                        index += 1
                    }
                }
                return false
            }

            func foundUnlimitedRecursionInFunction(_ fn: Variable, definedBy subrt: BlockGroup) -> Bool {
                return foundUnlimitedRecursionIn(subrt, as: {
                    ($0.op is CallFunction || $0.op is CallFunctionWithSpread) && $0.inputs[0] == fn
                })
            }

            func foundUnlimitedRecursionInConstructor(_ ctor: Variable, definedBy subrt: BlockGroup) -> Bool {
                return foundUnlimitedRecursionIn(subrt, as: {
                    ($0.op is Construct || $0.op is ConstructWithSpread) && $0.inputs[0] == ctor
                })
            }

            func foundUnlimitedRecursionInMethod(_ method: String, definedBy subrt: BlockGroup, isPrivate: Bool) -> Bool {
                return foundUnlimitedRecursionIn(subrt, as: { i in
                    // We are aggresive: we do not care about of the receiver
                    if let caller = i.op as? CallMethod, !isPrivate {
                        return caller.methodName == method
                    } else if let caller = i.op as? CallMethodWithSpread, !isPrivate {
                        return caller.methodName == method
                    } else if let caller = i.op as? CallPrivateMethod, isPrivate {
                        return caller.methodName == method
                    } else {
                        return false
                    }
                })
            }

            func foundUnlimitedRecursionInPropertyGetSet(
                _ property: String, definedBy subrt: BlockGroup,
                isSet: Bool, isPrivate: Bool
            ) -> Bool {
                return foundUnlimitedRecursionIn(subrt, as: { i in
                    // We are aggresive: we do not care about of the receiver
                    if let p = i.op as? GetProperty, !isSet && !isPrivate {
                        return p.propertyName == property
                    } else if let p = i.op as? SetProperty, isSet && !isPrivate  {
                        return p.propertyName == property
                    } else if let p = i.op as? GetPrivateProperty, !isSet && isPrivate {
                        return p.propertyName == property
                    } else if let p = i.op as? SetPrivateProperty, isSet && isPrivate  {
                        return p.propertyName == property
                    } else {
                        return false
                    }
                })
            }

            // Check subroutines one by one. Note, our checks are NEVER complete. Just some heuristic rules.
            for subrt in program.code.findAllSubroutines() {
                let definition = program.code[subrt.head]
                switch definition.op {
                case is BeginAnyFunction:
                    if foundUnlimitedRecursionInFunction(definition.output, definedBy: subrt) {
                        return true
                    }
                case is BeginConstructor:
                    if foundUnlimitedRecursionInConstructor(definition.output, definedBy: subrt) {
                        return true
                    }
                case is BeginObjectLiteralMethod:
                    if foundUnlimitedRecursionInMethod(
                        (definition.op as! BeginObjectLiteralMethod).methodName, definedBy: subrt, isPrivate: false
                    ) {
                        return true
                    }
                case  is BeginObjectLiteralComputedMethod:
                    break  // We cannot handle this as the method are computed (either Symbols or an unknown String)
                case is BeginObjectLiteralGetter:
                    if foundUnlimitedRecursionInPropertyGetSet(
                        (definition.op as! BeginObjectLiteralGetter).propertyName, definedBy: subrt, isSet: false, isPrivate: false
                    ) {
                        return true
                    }
                case is BeginObjectLiteralSetter:
                    if foundUnlimitedRecursionInPropertyGetSet(
                        (definition.op as! BeginObjectLiteralSetter).propertyName, definedBy: subrt, isSet: true, isPrivate: false
                    ) {
                        return true
                    }
                case is BeginClassConstructor:
                    let cls = program.code.findClassDefinition(for: definition).output
                    if foundUnlimitedRecursionInConstructor(cls, definedBy: subrt) {
                        return true
                    }
                case is BeginClassInstanceMethod:
                    if foundUnlimitedRecursionInMethod(
                        (definition.op as! BeginClassInstanceMethod).methodName, definedBy: subrt, isPrivate: false
                    ) {
                        return true
                    }
                case is BeginClassStaticMethod:
                    if foundUnlimitedRecursionInMethod(
                        (definition.op as! BeginClassStaticMethod).methodName, definedBy: subrt, isPrivate: false
                    ) {
                        return true
                    }
                case is BeginClassPrivateInstanceMethod:
                    if foundUnlimitedRecursionInMethod(
                        (definition.op as! BeginClassPrivateInstanceMethod).methodName, definedBy: subrt, isPrivate: false
                    ) {
                        return true
                    }
                case is BeginClassPrivateStaticMethod:
                    if foundUnlimitedRecursionInMethod(
                        (definition.op as! BeginClassPrivateStaticMethod).methodName, definedBy: subrt, isPrivate: false
                    ) {
                        return true
                    }
                case is BeginClassInstanceGetter:
                    if foundUnlimitedRecursionInPropertyGetSet(
                        (definition.op as! BeginClassInstanceGetter).propertyName, definedBy: subrt, isSet: false, isPrivate: false) {
                        return true
                    }
                case is BeginClassInstanceSetter:
                    if foundUnlimitedRecursionInPropertyGetSet(
                        (definition.op as! BeginClassInstanceSetter).propertyName, definedBy: subrt, isSet: true, isPrivate: false) {
                        return true
                    }
                case is BeginClassStaticGetter:
                    if foundUnlimitedRecursionInPropertyGetSet(
                        (definition.op as! BeginClassStaticGetter).propertyName, definedBy: subrt, isSet: false, isPrivate: false) {
                        return true
                    }
                case is BeginClassStaticSetter:
                    if foundUnlimitedRecursionInPropertyGetSet(
                        (definition.op as! BeginClassStaticSetter).propertyName, definedBy: subrt, isSet: true, isPrivate: false) {
                        return true
                    }
                default:
                    break
                }
            }
            return false  // We optimistically assume the program is infinite-recursion free.
        }

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

        return !containsUnlimitedRecursions() && isExecStdoutDeterm()
    }
}
