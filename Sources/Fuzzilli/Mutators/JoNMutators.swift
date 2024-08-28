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
            b.build(n: n / 2, by: .generating)
        }
        return b.finalize()
    }

    /// Create a random neutral loop.
    ///
    /// Let's embed the neutral loop into a brand new, small program which has no
    /// connections to the program under mutation
    public func randomNeutralLoop(n: Int = 10, forMutating program: Program) -> Program {
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

/// A simple JIT mutator that inserts a neutral loop into a random program point
public class PlainInsNeuLoopMutator: JITMutator {

    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, canBeInLoop: false)
    }

    override func canMutateInstruction(_ i: Instruction) -> Bool {
        return (
            // We are a plain instruction mutator, we don't work in subroutines
            !contextAnalyzer.context.contains(.subroutine) &&
            // We stay away from code strings (see JoNMutators)
            !contextAnalyzer.context.contains(.codeString)
        )
    }

    override func mutate(_ i: Instruction, _ b: ProgramBuilder) {
        b.adopt(i)
        b.append(b.randomNeutralLoop(forMutating: progUnderMut!))
    }
}

/// A JoN mutator is basically a subroutine mutator which performs JoN mutations  on subroutines
public class JoNMutator: BaseSubroutineMutator {
    let canBeInLoop: Bool
    var progUnderMut: Program? = nil

    var contextAnalyzer = ContextAnalyzer()
    var deadCodeAnalyzer = DeadCodeAnalyzer()

    init(name: String? = nil, maxSimultaneousMutations: Int = 1, canBeInLoop: Bool = false) {
        self.canBeInLoop = canBeInLoop
        // As we will add a try-catch block over the whole program.
        // Our mutations for subroutines are performed at depth 1.
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, mutateSubrtsAtDepth: 0)
    }

    override func beginMutation(of p: Program, using b: ProgramBuilder) {
        progUnderMut = p
        contextAnalyzer = ContextAnalyzer()
        deadCodeAnalyzer = DeadCodeAnalyzer()
    }
    
    override func canMutate(_ s: Instruction?, _ i: Instruction) -> Bool {
        contextAnalyzer.analyze(i)
        deadCodeAnalyzer.analyze(i)
        return (
            // We must be in a normal .javascript context
            contextAnalyzer.context.contains(.javascript) &&
            // We cannot within a loop; otherwise, we might never stop...
            (canBeInLoop || !contextAnalyzer.context.contains(.loop)) &&
            // We don't insert code in a code string as the inserted code
            // may be executed by an eval in aother location. Once the
            // inserted code is syntax-invalid, we canont capture it early.
            !contextAnalyzer.context.contains(.codeString) &&
            // We cannot be any dead code
            !deadCodeAnalyzer.currentlyInDeadCode &&
            // We then delegate to our children for further checks
            canMutateSubroutine(s, i)
        )
    }

    override func endMutation(of p: Program, using b: ProgramBuilder) {
        // TODO: Use a FixupMutator to fix up the program like removing unneeded try-catches.
        progUnderMut = nil
    }

    func adoptSubroutineByDefault(_ subrt: [Instruction], _ b: ProgramBuilder) {
        for instr in subrt {
            b.adopt(instr)
        }
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
///     f() {
///       ...
///       try {
///         for (...) {}                   // Try OSR-compiling f()
///       } catch {
///         // do nothing                  // Dismiss any unexpected
///       }
///       ...
///     }
///
/// The inserted neutral loop are wrapped by a try-catch block to dismiss any possble exceptions.
public class InsNeuLoopForJITMutator: JoNMutator {

    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, canBeInLoop: false)
    }

    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        return s != nil && !contextAnalyzer.context.contains(.objectLiteral) // We can mutate any subroutines
    }
    
    override func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        guard let progUnderMut = progUnderMut else {
            adoptSubroutineByDefault(subrt, b)
            return // No available program points
        }
        // We can only insert our loop before instructions that are mutable
        let choices = (0..<subrt.count-1).filter({ mutable[$0] })
        guard choices.count >= 1 else {
            adoptSubroutineByDefault(subrt, b)
            return // No available program points
        }
        let insertAt = chooseUniform(from: choices)
        for (index, instr) in subrt.enumerated() {
            b.adopt(instr)
            if index == insertAt {
                b.append(b.randomNeutralLoop(forMutating: progUnderMut))
            }
        }
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
///       for (...) {                               // Try OSR-compiling the subroutine
///         ...
///         if !flag { instr; flag = true; }        // Ensure instr is executed only once
///       }
///     } catch {
///       // do nothing                             // Dismiss any unexpected
///     } finally {
///       if !flag { instr; flag = true; }          // Ensure instr is executed only once
///     }
///
/// The flag is to control the execution of the instruction being wrapped.
public class WrapInstrForJITMutator: JoNMutator {

    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, canBeInLoop: false)
    }

    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        return (
            s != nil &&  // We can mutate any subroutines
            !contextAnalyzer.context.contains(.objectLiteral)
        )
    }

    override func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        guard subrt.count > 2, let progUnderMut = progUnderMut else {
            adoptSubroutineByDefault(subrt, b)
            return // No instructions to wrap
        }
        let choices = (1..<subrt.count-1).filter({
            // TODO: Avoid wrapping instructions with side effects.
            mutable[$0-1] && // The array mutable indicates if we can insert any code *after* that instruction. As our loop is about to wrap it, we have to check the program point before any instruction.
            !subrt[$0].isJump && // We cannot wrap any control-flow instructions
            !subrt[$0].isBlock && // We cannot wrap block starts and ends
            !subrt[$0].isCall && // We prefer not to wrapping calls as it is not atomic
            !subrt[$0].isGuarded && // We prefer not to wrapping guarded operations
            !(subrt[$0].op is Eval) && // We prefer not to wrapping an eval instruction
            !(subrt[$0].op is Await) && // We prefer not to wrapping an await instrcution
            !(subrt[$0].op is LoadBuiltin) && // We prefer not to wrapping an await instrcution
            !(subrt[$0].op is LoadNamedVariable) && // We prefer not to wrapping an instrcution with a predefined name
            !(subrt[$0].op is StoreNamedVariable) && // We prefer not to wrapping an instrcution with a predefined name
            !(subrt[$0].op is DefineNamedVariable) && // We prefer not to wrapping an instrcution with a predefined name
            !(subrt[$0].op is ConfigureElement) && // We prefer not to wrapping property setting instructions; they ain't atomc
            !(subrt[$0].op is ConfigureProperty) && // We prefer not to wrapping property setting instructions; they ain't atomc
            !(subrt[$0].op is ConfigureComputedProperty) && // We prefer not to wrapping property setting instructions; they ain't atomc
            subrt[$0].numOutputs <= 1 // We avoid wrapping instructions with multiple outputs
        })
        guard choices.count > 1 else {
            adoptSubroutineByDefault(subrt, b)
            return // No instructions to wrap
        }
        let wrapAt = chooseUniform(from: choices)
        for (index, instr) in subrt.enumerated() {
            if index == wrapAt {
                // We create a container to save both the flag and instr's output
                let container = b.createArray(with: [b.loadBool(false), b.loadNull()])
                // Wrap the loop by a try-catch-finally block to avoid any unexpected behavior
                b.buildTryCatchFinally(tryBody: {
                    b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
                        // Append a brand new program so that it has no connections to us
                        b.append(b.randomProgram(n: defaultSmallCodeBlockSize, forMutating: progUnderMut))
                        // Check if instr has ben executed in prior iterations and skip
                        // its execution if already; otherwise, execute it and set the flag
                        let flag = b.getElement(0, of: container)
                        b.buildIf(b.unary(.LogicalNot, flag)) {
                            let newInstrOut = b.replicate(instr)
                            if instr.hasOneOutput {
                                b.setElement(1, of: container, to: newInstrOut[0])
                            }
                            // We now move the set after executing instr as there're channces
                            // that instr throw exceptions. In this case, our catch block will
                            // dismiss it. We have to re-execute it to make the exceptions thrown
                            // again. To avoid cases that exeucting the instruction twice (even
                            // though throwing exceptions) may bring side effects, we choose to
                            // not wrap instructions with side effects (like calls).
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
                        // We set the flag prior to executing instr in this finally
                        // block because we cannot execute it again even it fails.
                        b.setElement(0, of: container, to: b.loadBool(true))
                        let newInstrOut = b.replicate(instr)
                        if instr.hasOneOutput {
                            b.setElement(1, of: container, to: newInstrOut[0])
                        }
                    }
                })
                // Export instr's result in the container to its output variable
                if instr.hasOneOutput {
                    let instrOut = b.adoptAndDefine(for: instr.output)
                    b.reassign(instrOut, from: b.getElement(1, of: container))
                }
            } else {
                b.adopt(instr)
            }
        }
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
///       if flag {           // Ensure all rest in f() are unexecuted
///          ...
///          return
///       }
///       ...
///     }
///
///     flag = true           // Ensure to execute the prologue
///     try {
///       for (...) {
///         ...
///         f(...)            // Try JIT-compiling the subroutine f()
///       }
///     } catch {
///       // do nothing       // Dismiss any unexpected behavior
///     } finally {
///       flag = false        // Ensure to execute the original f()
///     }
///
///     f(...)                // Might be executed in JIT or de-optimized
///
/// To ensure JIT compilation, the flag is set to true and the subroutine is executed
/// mutiple times. After that, the flag is set to false and the call is re-executed.
public class CallSubrtForJITMutator: JoNMutator {

    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, canBeInLoop: false)
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

    override func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        guard let progUnderMut = progUnderMut else {
            adoptSubroutineByDefault(subrt, b)
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
            if (
                instr.isCall &&
                // CallSuperConstructor does not require a target and
                // there are chances that it does not have any inputs
                instr.hasInputs &&
                instr.inputs[0] == subrtBeforeMut
            ) {
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
}

/// A JoN mutator that try to de-optimize and possibly re-compile a JIT-ed subroutine.
///
/// This is an opposite of CallSubrtForJITMutator. In particular, this mutator inserts a subroutine call `s` before a call `c`
/// inside a loop. The inserted subroutine call `s` have totally different arguments from the call `c` while `s` is executed
/// at some iterations before the last iteration. This tries to make the subroutine be de-optmized and might also be recompiled.
///
///     func f(...) {
///       ...
///     }
///
///     loop {
///       f(...);
///     }
///
///       v
///
///     func f(...) {
///       if flag {            // Ensure all rest in f() are unexecuted
///          ...
///          return            // Early to avoid executing the original code of f()
///       }
///       ...
///     }
///
///     loop N {
///       if (exec h times) {  // Execute the inserted call at some intermediate iters
///         flag = true;
///         f(...);            // Try to de-optimize f(...)
///         flag = false;
///       }
///       f(...);              // If h is lower enough, f(...) may be re-compiled
///     }
///
/// To ensure the semantics are untouched, we also inserted an addition flag `flag` to control our behavior.  As we are
/// not able to count how many iterations have left, we created a additional counter to counter the number of times that
/// `f(...)` has been executed. We enable the call if the time has exceeded a predefined number.
public class CallSubrtForDeOptMutator: JoNMutator {

    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        super.init(name: name, maxSimultaneousMutations: maxSimultaneousMutations, canBeInLoop: true)
    }

    // We are a fake JoN mutator so we abandon all JoNMutator's methods
    override func beginMutation(of p: Program, using b: ProgramBuilder) {
        fatalError("This method cannot be called !!")
    }

    override func canMutate(_ s: Instruction?, _ i: Instruction) -> Bool {
        fatalError("This method cannot be called !!")
    }

    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        fatalError("This method cannot be called !!")
    }

    override func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ builder: ProgramBuilder) {
        fatalError("This method cannot be called !!")
    }

    override func endMutation(of p: Program, using b: ProgramBuilder) {
        fatalError("This method cannot be called !!")
    }
    // We are a fake JoN mutator so we abandon all JoNMutator's methods

    override func mutate(_ program: Program, using b: ProgramBuilder, for fuzzer: Fuzzer) -> Program? {
        let subroutines = program.code.findAllSubroutines(at: 0).filter { bg in
            ( // TODO: Support more function types
                program.code[bg.head].op is BeginPlainFunction ||
                program.code[bg.head].op is BeginArrowFunction
            ) // We currently only support these types
        }.map { bg in
            Block(head: bg.head, tail: bg.tail, in: program.code)
        }
        guard subroutines.count > 0 else {
            return nil // No subroutines to mutate
        }

        // A map of "subroutine definition index" -> ("subroutine", "calls to subroutine")
        var candidates = [Int: (Block, [Instruction])]()
        var contextAnalyzer = ContextAnalyzer()

        // Let's find all appropriate calls to one of the subroutines
        for instr in program.code {
            contextAnalyzer.analyze(instr)
            if (
                instr.isCall && // We only focus on calls to subroutines
                ( // TODO: Consider focus on more types of calls
                    instr.op is CallFunction ||
                    instr.op is CallFunctionWithSpread
                ) && // We currently only support CallFunction
                contextAnalyzer.context.contains(.loop) // We focus on calls inside loops
            ) {
                let callee = instr.inputs[0]
                // Check if it is one of our declared subroutine
                for subrt in subroutines {
                    let definition = program.code[subrt.head]
                    if definition.hasOutputs && definition.outputs[0] == callee {
                        if !candidates.keys.contains(definition.index) {
                            candidates[definition.index] = (subrt, [Instruction]())
                        }
                        var calls = candidates[definition.index]
                        calls?.1.append(instr)
                        candidates[definition.index] = calls
                    }
                }
            }
        }

        guard candidates.count > 0 else {
            return nil // No candidates found
        }

        // Sample subroutines and its calls for mutation
        var toMutateSubrtDefIndices = Set<Int>()
        for _ in 0..<Int.random(in: 1...maxSimultaneousMutations) {
            toMutateSubrtDefIndices.insert(chooseUniform(from: candidates.map{ k, _ in k }))
        }

        var toMutateSubrts = [Block]()
        var toMutateCallIndices = [Int]()
        for subrtDefIndex in toMutateSubrtDefIndices {
            if let pair = candidates[subrtDefIndex] {
                toMutateSubrts.append(pair.0)   // We need to insert code inside the code
                toMutateCallIndices.append(pair.1[0].index) // We only mutate the very first call
            }
        }

        var flagCountersAfterMut = [Variable: Variable]()

        // Perform mutations: For subroutines, we add a prologue; For calls, we add a pre-call.
        b.adopting(from: program) {
            var index = 0, toMutateIndex = 0
            while index < program.size {
                let instr = program.code[index]
                if toMutateIndex < toMutateSubrts.count && index == toMutateSubrts[toMutateIndex].head {
                    // Mutate the subroutines
                    let subrtBlock = toMutateSubrts[toMutateIndex]
                    let subrtInstrs = [Instruction](program.code[subrtBlock])
                    flagCountersAfterMut[subrtInstrs[0].output] = mutateSubroutine(subrtInstrs, using: b)
                    index = toMutateSubrts[toMutateIndex].tail + 1
                    toMutateIndex += 1
                } else if toMutateCallIndices.contains(index)  {
                    // Mutate its call
                    mutateCallToSubroutine(
                        instr,
                        with: flagCountersAfterMut[instr.input(0)]!,
                        using: b
                    )
                    index += 1
                } else {
                    b.adopt(instr)
                    index += 1
                }
            }
        }
        
        return b.finalize()
    }
    
    private func mutateSubroutine(_ subrt: [Instruction], using b: ProgramBuilder) -> Variable {
        // Create a flag and a counter; again we insert them into a container
        let flagAndCounter = b.createArray(with: [b.loadBool(false), b.loadInt(0)])

        // Adopt the subroutine first; this
        b.adopt(subrt[0])

        // Insert a neutral prologue into the subrt first
        let prologue = b.randomProgram(n: 6)
        b.adopting(from: prologue) {
            b.buildIf(b.compare(
                b.getElement(0, of: flagAndCounter),
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
        
        return flagAndCounter
    }

    private func mutateCallToSubroutine(_ subrtCall: Instruction, with flagAndCounter: Variable, using b: ProgramBuilder) {
        let subrtAfterMut = b.adopt(subrtCall.input(0))
        // Set to begin calling the prologue
        b.setElement(0, of: flagAndCounter, to: b.loadBool(true))
        b.buildTryCatchFinally(tryBody: {
            // TODO: Backtrack and utilize the loop iteration variables
            let condition = b.compare(
                b.getElement(1, of: flagAndCounter),
                with: b.loadInt(Int64(defaultMaxLoopTripCountInJIT / 2)),
                using: .greaterThanOrEqual
            )
            b.buildIf(condition) {
                b.append(b.randomProgram(n: 6))
                // Let's reuse the types different from the call so that the call
                // is called in the interpreter stack (but might be recompiled,
                // depending on the rest number of iterations).
                b.callFunction(subrtAfterMut, withArgs: b.randomVariables(
                    preferablyNotOfTypes: subrtCall.inputs[1..<subrtCall.numInputs].map{
                        b.type(of: $0)
                    }
                ))
            }
        }, catchBody: { _ in
            // We dismiss the exception to avoid any unexpected behaviors
            return
        }, finallyBody: {
            // Set to stop calling the prologue
            b.setElement(0, of: flagAndCounter, to: b.loadBool(false))
        })
        // Adopt the call
        b.adopt(subrtCall)
        b.updateElement(1, of: flagAndCounter, with: b.loadInt(1), using: .Add)
    }
}

// TODO: Add some duck types and mutate by duck types
