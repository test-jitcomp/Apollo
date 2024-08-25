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

    /// Returns a list of random variables that are known to have the given types one by one.
    ///
    /// If there are no variables found for a type, create a new variable for it
    public func randomVariables(ofTypes types: [ILType]) -> [Variable] {
        return types.map({
            var v = randomVariable(ofType: $0)
            if v == nil {
               v = loadNull()
               setType(ofVariable: v!, to: $0)
            }
            return v!
        })
    }

    /// Returns a list of random variables that are not known to have the given types one by one.
    ///
    /// If there are no variables found for a type, return a random variable (regardless of the type)
    public func randomVariables(preferablyNotOfTypes types: [ILType]) -> [Variable] {
        return types.map({
            randomVariable(preferablyNotOfType: $0) ?? randomVariable()
        })
    }
}

// TODO: Support configuring loop trips. Type checking to ensure type-confusion and de-optimization.
// TODO: Remove duplicate code among this file, JIT1Function, JIT2Function, and JITTrickyFunction ProgramTemplates.
// TODO: Add some more complicated mutators involving multiple rounds of JIT compilation, de-optimization, and re-compilation

/// A JIT mutator is basically an instruction mutator
public class JITMutator: BaseInstructionMutator {
    var contextAnalyzer = ContextAnalyzer()
    var progUnderMut: Program? = nil

    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        contextAnalyzer = ContextAnalyzer()
        progUnderMut = p
    }

    final public override func canMutate(_ i: Instruction) -> Bool {
        contextAnalyzer.analyze(i)
        return (
            // We must be in a normal .javascript context
            contextAnalyzer.context.contains(.javascript) &&
            // Basically, we cannot apply mutation inside a loop, otherwise,
            // adding new loops may cause the program to run overly long.
            !contextAnalyzer.context.contains(.loop) &&
            // Then we delegate to our children for further checks
            canMutateInstruction(i)
        )
    }

    public override func endMutation(of p: Program, using b: ProgramBuilder) {
        // TODO: Use a FixupMutator to fix up the program like removing unneeded try-catches.
        progUnderMut = nil
    }

    /// Overridden by child classes.
    /// Check if the instruction can be mutated by the mutator
    func canMutateInstruction(_ i: Instruction) -> Bool {
        fatalError("This method must be overriden")
    }
}

/// A JIT mutator that inserts a loop into a subroutine, trying to make the subroutine under insertion JIT compiled.
///
/// To ensure JIT compilation as much as possible, it insert a loop after a random instruction.
///
///     instr;
///
///        v
///
///     instr;
///     for (...) { ...; } // enable JIT compilation
///
/// The JIT compilation should be guaranteed; however, this depends on the loop trop.
public class SubrtJITCompMutator: JITMutator {

    override func canMutateInstruction(_ i: Instruction) -> Bool {
        return !contextAnalyzer.context.contains(.subroutine)
    }

    public override func mutate(_ i: Instruction, _ b: ProgramBuilder) {
        b.adopt(i)
        // Insert a loop after the instruction to make the surrounding subroutine JIT compiled
        b.buildPrefix()
        // In (and only in) JSC, loop iterations counts 1/15 of method calls.
        // TODO: Change the iteration account according to the profile
        // TODO: Randomly pick an int variable as the loop trip
         b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
            b.build(n: defaultSmallCodeBlockSize, by: .generating)
        }
    }
}

/// A JIT mutator that wraps a function/method call with a loop to enable JIT compilation.
/// 
/// To ensure JIT compilation as much as possible, it wraps a random function/method call instruction inside a loop. 
///
///     foo(a, b); 
///
///        v
///
///     for (...) { ...; foo(a, b); ...; } // enable JIT compilation
///
/// The JIT compilation should be guaranteed; however, this depends on the loop trop.
public class CallJITCompMutator: JITMutator {

    override func canMutateInstruction(_ i: Instruction) -> Bool {
        return (
            i.isCall &&
            (i.op is CallMethod || i.op is CallFunction) // TODO: Remove this to support all types of calls
        )
    }

    public override func mutate(_ i: Instruction, _ b: ProgramBuilder) {
        // Adopt the instruction first otherwise the output variable won't be visible
        b.adopt(i)
        // Wrap the instruction with a loop such that the called function/method can be JITted
        b.buildPrefix()
        b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
            b.build(n: defaultSmallCodeBlockSize / 2, by: .generating)
            b.replicate(i)
            b.build(n: defaultSmallCodeBlockSize / 2, by: .generating)
        }
    }
}

/// A JIT mutator that wraps a function/method call to enable JIT compilation then trigger de-optimization.
/// 
/// To ensure JIT compilation as much as possible, it wraps a random function/method call instruction inside a loop. 
/// To trigger de-optimization, it tries to call the same function/method with different arguments inside another loop.
///
///     foo(a, b); 
///
///        v
///
///     for (...) { ...; foo(a, b); ...; } // enable JIT compilation
///     ...;
///     foo(c, d);                         // trigger de-optimization
///
/// The de-optimization is not guaranteed, but possibly to occur.
public class CallDeOptMutator: CallJITCompMutator {

    public override func mutate(_ i: Instruction, _ b: ProgramBuilder) {
        // Wrap the instruction by a loop to enable JIT compilation
        super.mutate(i, b)

        // Create some new variables for future use
        b.buildPrefix();
        b.build(n: defaultSmallCodeBlockSize)

        // Change the argument of the called method/function, trying to trigger a de-optimization
        // Shall not use ProgramBuilder.randomArgument() since this API tries to find variables that
        // match the argument type of the called function/method. This contradicts our de-opt goal.
        switch (i.op) {
            case let op as CallFunction:
                let f = i.input(0)
                let argTypes = i.inputs[1..<i.numInputs].map({
                    b.type(of: $0)
                })
                let args = b.randomVariables(preferablyNotOfTypes: argTypes)
                b.callFunction(f, withArgs: args, guard: op.isGuarded)

            case let op as CallMethod:
                let m = op.methodName
                let obj = i.input(0) // TODO: It's safe to use another object with the same type?
                let argTypes = i.inputs[1..<i.numInputs].map({
                    b.type(of: $0)
                })
                let args = b.randomVariables(preferablyNotOfTypes: argTypes)
                b.callMethod(m, on: obj, withArgs: args, guard: op.isGuarded)

            default: // TODO: Support more instructions like CallFunctionWithSpread. See JsOperations.swift.
                preconditionFailure("Unsupported type of function/method call: ")
        }
    }
}

/// A JIT mutator that wraps a function/method call to enable JIT compilation, trigger de-optimization, and enable re-compilation.
/// 
/// To ensure JIT compilation as much as possible, it wraps a random function/method call instruction inside a loop. 
/// To trigger de-optimization and re-compilation, it tries to call the same function/method with different arguments inside another loop.
///
///     foo(a, b); 
///
///        v
///
///     for (...) { ...; foo(a, b); ...; }   // enable JIT compilation
///     ...;
///     foo(c, d);                           // trigger de-optimization
///     ...;
///     for (...) { ...; foo(e, f); ...; }   // try enabling re-compilation
///
/// Both de-optimization and re-compilation are not guaranteed, but possibly to occur.
public class CallReCompMutator: CallDeOptMutator {

    public override func mutate(_ i: Instruction, _ b: ProgramBuilder) {
        // Trigger JIT compilation then de-optimization on the instruction
        super.mutate(i, b)

        // Create some new variables for future use
        b.buildPrefix()
        b.build(n: defaultSmallCodeBlockSize);

        // Reuse the types of the arguments to try triggering a re-compilation
        b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
            switch (i.op) {
                case let op as CallFunction:
                    let f = i.input(0)
                    let argTypes = i.inputs[1..<i.numInputs].map({
                        b.type(of: $0)
                    })
                    let args = b.randomVariables(ofTypes: argTypes)
                    b.callFunction(f, withArgs: args, guard: op.isGuarded)

                case let op as CallMethod:
                    let m = op.methodName
                    let obj = i.input(0)
                    let argTypes = i.inputs[1..<i.numInputs].map({
                        b.type(of: $0)
                    })
                    let args = b.randomVariables(ofTypes: argTypes)
                    b.callMethod(m, on: obj, withArgs: args, guard: op.isGuarded)

                default: // TODO: Support more instructions like CallFunctionWithSpread. See JsOperations.swift.
                    preconditionFailure("Unsupported type of function/method call: ")
            }
        }
    }
}

