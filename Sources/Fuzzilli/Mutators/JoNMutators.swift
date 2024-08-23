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

extension ProgramBuilder {
    
    /// Build a random, small program from scratch
    public func randomProgram(
        n: Int = 10,
        forMutating program: Program? = nil,
        _ body: ((ProgramBuilder) -> ())? = nil
    ) -> Program {
        let b = fuzzer.makeBuilder(forMutating: program)
        if let body = body {
            body(b)
        } else {
            b.buildValues(n / 2)
            b.build(n: n / 2)
        }
        return b.finalize()
    }
    
    /// Create a random neutral loop.
    ///
    /// Let's embed the neutral loop into a brand new, small program which has no
    /// connections to the program under mutation
    func randomNeutralLoop(n: Int = 10, forMutating program: Program) -> Program {
        // We create a new program to avoid any connections to program
        return randomProgram(forMutating: program) { b in
            // We wrap by a try-catch to dismiss any possible exceptions
            b.buildTryCatchFinally(tryBody: {
                b.buildValues(n / 2)
                b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
                    b.build(n: n / 2, by: .generating)
                }
            }, catchBody: { _ in
                // We dismiss the exception to avoid any unexpected behaviors
                return
            })
        }
    }
}

/// A mutator which assists JoN mutation by inserting a checksum variable into a program.
class InsertChksumMutator: Mutator {

    override func mutate(_ program: Program, using b: ProgramBuilder, for fuzzer: Fuzzer) -> Program? {
        // Firstly, define a checksum variable: "var chksumContainer = [0xAB011]".
        // We create an array as the container for our checksum as if we used a
        // checksum variable, of which the operations are performed in the try-block,
        // is not visible in the finally-block in FuzzIL.
        let chkSumContainer = b.createIntArray(with: [0xAB0110])
        var contextAnalyzer = ContextAnalyzer()

        // Let's insert a try-catch to ensure that the checksum are always printed
        b.buildTryCatchFinally(tryBody: {
            b.adopting(from: program) {
                for instr in program.code {
                    b.adopt(instr)
                    contextAnalyzer.analyze(instr)
                    // Perform some operations over the checksum:
                    // "checkSumContainer[0] = operations involving chksumContainer[0]"
                    if probability(0.2) && contextAnalyzer.context.isSuperset(of: .javascript) {
                        let chkSumVal = b.binary(
                            b.getElement(0, of: chkSumContainer),
                            b.randomVariable(ofType: .integer) ?? b.loadInt(b.randomInt()),
                            with: withEqualProbability(
                                {.Add}, {.Sub}, {.Mul},
                                {.BitAnd}, {.BitOr}, {.Xor},
                                {.LogicOr}, {.LogicAnd}
                            )
                        )
                        b.setElement(0, of: chkSumContainer, to: chkSumVal)
                    }
                }
            }
        }, finallyBody: {
            // Finally, print the value of the checksum:
            // "print(`Checksum: ${checkSumContainer[0]}`)"
            let chksumMsg = b.binary(
                b.loadString("Checksum: "),
                b.getElement(0, of: chkSumContainer),
                with: .Add
            )
            b.eval("__compat_out__(%@)", with: [chksumMsg])
        })

        return b.finalize()
    }
}

/// A JoN mutator is basically a subroutine mutator
public class JoNMutator: SubroutineMutator {
    var contextAnalyzer = ContextAnalyzer()
    var deadCodeAnalyzer = DeadCodeAnalyzer()

    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        // As we will add a try-catch block over the whole program.
        // Our mutations for subroutines are performed at depth 1.
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, mutateSubrtsAtDepth: 1)
    }

    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        contextAnalyzer = ContextAnalyzer()
        deadCodeAnalyzer = DeadCodeAnalyzer()
    }
    
    final public override func canMutate(_ s: Instruction?, _ i: Instruction) -> Bool {
        contextAnalyzer.analyze(i)
        deadCodeAnalyzer.analyze(i)
        return (
            // We must be in a normal .javascript context
            contextAnalyzer.context.contains(.javascript) &&
            // We cannot within a loop; otherwise, we might never stop...
            !contextAnalyzer.context.contains(.loop) &&
            // We cannot be any dead code
            !deadCodeAnalyzer.currentlyInDeadCode &&
            // We then delegate to our children for further checks
            canMutateSubroutine(s, i)
        )
    }

    public override func endMutation(of p: Program, using b: ProgramBuilder) {
        // TODO: Use a FixupMutator to fix up the program like removing unneeded try-catches.
    }

    /// Overridden by child classes.
    /// Check if the subroutine can be mutated by the mutator
    func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        fatalError("This method must be overriden")
    }
}

/// A JoN mutator that inserts a neutral loop into a random program point of a subroutine,
/// trying to make the subroutine JIT compiled.
///
/// In particular, the neutral loop does not involve any connections to the program under
/// mutation and has no side effect which ensures the program after mutation being in the
/// same semantics as the program before being mutated.
///
///     subroutine() {
///       ...
///       try {
///         for (...) {}
///       } catch {
///         // do nothing
///       }
///       ...
///     }
///
/// The inserted neutral loop are wrapped by a try-catch block to dismiss any possble exceptions.
public class InsNeuLoopMutator: JoNMutator {
    var progUnderMut: Program? = nil
    
    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        super.beginMutation(of: p, using: b)
        progUnderMut = p
    }
    
    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        return s != nil && !contextAnalyzer.context.contains(.objectLiteral) // We can mutate any subroutines
    }
    
    override public func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        // We can only insert our loop before instructions that are mutable
        let insertAt = chooseUniform(from: (0..<subrt.count-1).filter({ mutable[$0] }))
        for (index, instr) in subrt.enumerated() {
            b.adopt(instr)
            if index == insertAt {
                b.append(b.randomNeutralLoop(forMutating: progUnderMut!))
            }
        }
    }

    public override func endMutation(of p: Program, using b: ProgramBuilder) {
        super.endMutation(of: p, using: b)
        progUnderMut = nil
    }
}

/// A JoN mutator  that wraps an instruction by a neutral loop which ensures the statement to be executed only once.
///
/// In particular, the neutral loop does not involve any connections to the program under mutation and has no side effect
/// except for executing the wrapped statement only once. Also the neutral loop is wrapped by a try-finally block which
/// double-checks  that the instruction is indeed being executed.
///
///     instr
///
///       v
///
///     flag = false
///     try {
///       for (...) {
///         ...
///         if !flag { instr; flag = true; }
///       }
///     } catch {
///       // do nothing
///     } finally {
///       if !flag { instr; flag = true; }
///     }
///
/// The flag is to control the execution of the instruction being wrapped.
public class WrapInstrMutator: JoNMutator {
    var progUnderMut: Program? = nil

    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        super.beginMutation(of: p, using: b)
        progUnderMut = p
    }

    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        return (
            s != nil &&  // We can mutate any subroutines
            !contextAnalyzer.context.contains(.objectLiteral)
        )
    }

    override public func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        guard subrt.count > 2 else {
            return // No instructions to wrap
        }
        let wrapAt = chooseUniform(from: (1..<subrt.count-1).filter({
            mutable[$0-1] && // The array mutable indicates if we can insert any code *after* that instruction. As our loop is about to wrap it, we have to check the program point before any instruction.
            !subrt[$0].isJump && // We cannot wrap any control-flow instructions
            !subrt[$0].isBlock && // We cannot wrap block starts and ends
            !(subrt[$0].op is Eval) && // We prefer not to wrapping an eval instruction
            !(subrt[$0].op is Await) && // We prefer not to wrapping an await instrcution
            subrt[$0].numOutputs <= 1 // We avoid wrapping instructions with multiple outputs
        }))
        for (index, instr) in subrt.enumerated() {
            if index == wrapAt {
                // We create a container to save both the flag and instr's output
                let container = b.createArray(with: [b.loadBool(false), b.loadNull()])
                // Wrap the loop by a try-catch-finally block to avoid any unexpected behavior
                b.buildTryCatchFinally(tryBody: {
                    b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
                        // Append a brand new program so that it has no connections to us
                        b.append(b.randomProgram(n: defaultSmallCodeBlockSize, forMutating: progUnderMut!))
                        // Check if instr has ben executed in prior iterations and skip
                        // its execution if already; otherwise, execute it and set the flag
                        let flag = b.getElement(0, of: container)
                        b.buildIf(b.unary(.LogicalNot, flag)) {
                            // We replicate() instead of adopt() as we are in a loop;
                            // the output variable is invisible to outer scopes.
                            // So we save the output value to our container.
                            let newInstrOut = b.replicate(instr)
                            if instr.hasOneOutput {
                                b.setElement(1, of: container, to: newInstrOut[0])
                            }
                            b.setElement(0, of: container, to: b.loadBool(true))
                        }
                    }
                }, catchBody: { _ in
                    // We dismiss the exception to avoid any unexpected behaviors
                    return
                }, finallyBody: {
                    // Double-check to make sure instr is indeed executed once.
                    let flag = b.getElement(0, of: container)
                    b.buildIf(b.unary(.LogicalNot, flag)) {
                        let newInstrOut = b.replicate(instr)
                        if instr.hasOneOutput {
                            b.setElement(1, of: container, to: newInstrOut[0])
                        }
                        b.setElement(0, of: container, to: b.loadBool(true))
                    }
                })
                // Export instr's result in the container to its output variable
                if instr.hasOneOutput {
                    let instrOut = b.adoptAndDefine(for: instr.output)
                    b.reassign(b.getElement(1, of: container), to: instrOut)
                }
            } else {
                b.adopt(instr)
            }
        }
    }

    public override func endMutation(of p: Program, using b: ProgramBuilder) {
        super.endMutation(of: p, using: b)
        progUnderMut = nil
    }
}

/// A JoN mutator that pre-calls a subroutine to make it JIT compile.
///
/// In particular, the pre-call is inserted right before a call to the subroutine. To avoid change the semantics
/// of the program, the mutator inserts a neutral prologue into the subroutine. The prologue is controled by
/// a flag, which when set to true, drives the subroutine to early return.
///
///     func f(...) {
///       ...
///     }
///
///     f(...)
///
///       v
///
///     func f(...) {
///       if flag {
///          ...
///          return
///       }
///       ...
///     }
///
///     flag = true
///     try {
///       for (...) {
///         ...
///         f(...)
///       }
///     } catch {
///       // do nothing
///     }
///      finally {
///       flag = false
///     }
///
///     f(...)
///
/// To ensure JIT compilation, the flag is set to true and the subroutine is executed mutiple times. After that,
/// the flag is set to false and the call is re-executed.
public class CallSubrtMutator: JoNMutator {
    var progUnderMut: Program? = nil

    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        super.beginMutation(of: p, using: b)
        progUnderMut = p
    }

    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        return (
            s != nil &&  // We can mutate any subroutines
            ( // TODO: Support more function types
                s!.op is BeginPlainFunction ||
                s!.op is BeginArrowFunction
            ) && // We currently only support these types
            !contextAnalyzer.context.contains(.objectLiteral)
        )
    }

    override public func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        guard let progUnderMut = progUnderMut else {
            return
        }

        // Create a flag; again we insert it into a container
        let flagContainer = b.createArray(with: [b.loadBool(false)])

        // Adopt the subroutine first; this
        b.adopt(subrt[0])

        let subrtBeforeMut = subrt[0].output
        let subrtAfterMut = b.adopt(subrtBeforeMut)

        // Insert a neutral prologue into the subrt first
        let prologue = b.randomProgram(n: 6)
        b.adopting(from: prologue) {
            b.buildIf(b.compare(
                b.getElement(0, of: flagContainer),
                with: b.loadBool(true),
                using: .equal
            )) {
                for instr in prologue.code {
                    b.adopt(instr)
                }
                b.doReturn(b.loadNull())
            }
        }

        // Adopt the rest instructions
        for instr in subrt[1..<subrt.count] {
            b.adopt(instr)
        }

        // Insert a immediate call to the subrt to JIT compile it

        // Find the very first call to the subroutine; we'll reuse it.
        var subrtCall: Instruction? = nil
        for instr in progUnderMut.code {
            if instr.isCall && instr.inputs[0] == subrtBeforeMut {
                subrtCall = instr
                break
            }
        }

        // Set to begin calling the prologue
        b.setElement(0, of: flagContainer, to: b.loadBool(true))
        b.buildTryCatchFinally(tryBody: {
            b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
                b.append(b.randomProgram(n: 6))
                if let subrtCall = subrtCall {
                    // Let's reuse the types of the first call so that the first
                    // call is called in the JIT stack (but might be deoptimized,
                    // depending on the JIT compilier's compilation strategy).
                    b.callFunction(subrtAfterMut, withArgs: b.randomVariables(
                        ofTypes: subrtCall.inputs[1..<subrtCall.numInputs].map({ b.type(of: $0) })
                    ))
                } else {
                    // Let's build some random arguments
                    b.callFunction(subrtAfterMut, withArgs: b.randomArguments(
                        forCalling: subrtAfterMut
                    ))
                }
            }
        }, catchBody: { _ in
            // We dismiss the exception to avoid any unexpected behaviors
            return
        }, finallyBody: {
            // Set to stop calling the prologue
            b.setElement(0, of: flagContainer, to: b.loadBool(false))
        })
    }

    public override func endMutation(of p: Program, using b: ProgramBuilder) {
        super.endMutation(of: p, using: b)
        progUnderMut = nil
    }
}

// TODO: Add some duck types and mutate by duck types
