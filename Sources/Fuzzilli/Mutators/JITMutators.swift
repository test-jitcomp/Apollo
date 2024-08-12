// Copyright 2019 Cong Li (congli@smail.nju.edu.cn, cong.li@inf.ethz.ch)
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
               v = nextVariable()
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

/// A JIT mutator is basically an instruction mutator
public class JITMutator: BaseInstructionMutator {}

/// A JIT mutator that inserts a loop into a subroutine, trying to make the subroutine under insertion JIT compiled.
public class SubRtJITMutator: JITMutator {
    private var contextAnalyzer = ContextAnalyzer()

    public override func beginMutation(of program: Program) {
        contextAnalyzer = ContextAnalyzer()
    }

    public override func canMutate(_ instr: Instruction) -> Bool {
        contextAnalyzer.analyze(instr)
        return !contextAnalyzer.context.contains(.subroutine)
    }

    public override func mutate(_ instr: Instruction, _ builder: ProgramBuilder) {
        // TODO: In (and only in) JSC, loop iterations counts 1/15 of method calls.
        builder.buildPrefix()
        builder.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT * 15) {
            builder.build(n: defaultSmallCodeBlockSize, by: .generating)
        }
        builder.adopt(instr)
    }
}

/// A JIT mutator that wraps a function/method call with a loop to enable JIT compilation.
/// 
/// Specifically, this mutator targets fuzzing JIT compilers. 
/// To ensure JIT compilation as much as possible, it wraps a random function/method call instruction inside a loop. 
/// To trigger de-optimization, it tries to call the same function/method with different arguments inside another loop.
///
///     foo(a, b); 
///
///        v
///
///     for (...) { ...; foo(a, b); ...; } // enable JIT compilation
///
/// TODO: Support configuring loop trips. Type checking to ensure type-confusion and de-optimization.
/// TODO: Remove duplicate code among this Mutator, JIT1Function, JIT2Function, and JITTrickyFunction ProgramTemplates.
public class CallJITCompMutator: JITMutator {

    override public func canMutate(_ instr: Instruction) -> Bool {
        // TODO: Support more types of calls
        return instr.isCall && (instr.op is CallMethod || instr.op is CallFunction)
    }

    public override func mutate(_ instr: Instruction, _ builder: ProgramBuilder) {
        // Wrap instr with a loop such that the called function/method can be JITted
        builder.buildPrefix()
        // TODO: Randomly pick an int variable as the loop trip
        builder.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) { _ in
            builder.build(n: defaultSmallCodeBlockSize / 2, by: .generating)
            // TODO: Drop guarding to avoid being guarded by try-catch after lifting?
            builder.adopt(instr)
            builder.build(n: defaultSmallCodeBlockSize / 2, by: .generating)
        }
    }
}

/// A JIT mutator that wraps a function/method call to enable JIT compilation then trigger de-optimization.
/// 
/// Specifically, this mutator targets fuzzing JIT compilers. 
/// To ensure JIT compilation as much as possible, it wraps a random function/method call instruction inside a loop. 
/// To trigger de-optimization and re-compilation, it tries to call the same function/method with different arguments inside another loop.
///
///     foo(a, b); 
///
///        v
///
///     for (...) { ...; foo(a, b); ...; } // enable JIT compilation
///     ...;
///     foo(c, d);                         // trigger de-optimization
///
/// TODO: Support configuring loop trips. Type checking to ensure type-confusion and de-optimization.
/// TODO: Remove duplicate code among this Mutator, JIT1Function, JIT2Function, and JITTrickyFunction ProgramTemplates.
public class CallDeOptMutator: CallJITCompMutator {

    public override func mutate(_ instr: Instruction, _ builder: ProgramBuilder) {
        // Wrap instr by a loop to enable JIT compilation
        super.mutate(instr, builder)

        // Create some new variables for future use
        builder.buildPrefix();
        builder.build(n: defaultSmallCodeBlockSize)

        // Change the argument of the called method/function, trying to trigger a de-optimization
        // Shall not use ProgramBuilder.randomArgument() since this API tries to find variables that
        // match the argument type of the called function/method. This contradicts our de-opt goal.
        switch (instr.op) {
            case let op as CallFunction:
                let f = builder.adopt(instr.input(0))
                let argTypes = instr.inputs[1..<instr.numInputs].map({
                    builder.type(of: $0)
                })
                let args = builder.randomVariables(preferablyNotOfTypes: argTypes)
                builder.callFunction(f, withArgs: args, guard: op.isGuarded)

            case let op as CallMethod:
                let m = op.methodName
                let obj = builder.adopt(instr.input(0))
                let argTypes = instr.inputs[1..<instr.numInputs].map({
                    builder.type(of: $0)
                })
                let args = builder.randomVariables(preferablyNotOfTypes: argTypes)
                builder.callMethod(m, on: obj, withArgs: args, guard: op.isGuarded)

            default: // TODO: Support more instructions like CallFunctionWithSpread. See JsOperations.swift.
                preconditionFailure("Unsupported type of function/method call: ")
        }
    }
}

/// A JIT mutator that wraps a function/method call to enable JIT compilation, trigger de-optimization, and re-compile.
/// 
/// Specifically, this mutator targets fuzzing JIT compilers. 
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
///     for (...) { ...; foo(c, d); ...; }   // try enabling re-compilation
///
/// TODO: Support configuring loop trips. Type checking to ensure type-confusion and de-optimization.
/// TODO: Remove duplicate code among this Mutator, JIT1Function, JIT2Function, and JITTrickyFunction ProgramTemplates.
public class CallReCompMutator: CallDeOptMutator {

    public override func mutate(_ instr: Instruction, _ builder: ProgramBuilder) {
        // Trigger JIT compilation then de-optimization on instr
        super.mutate(instr, builder)

        // Create some new variables for future use
        builder.buildPrefix()
        builder.build(n: defaultSmallCodeBlockSize);

        // Reuse the types of the arguments to try triggering a re-compilation
        builder.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
            switch (instr.op) {
                case let op as CallFunction:
                    let f = builder.adopt(instr.input(0))
                    let argTypes = instr.inputs[1..<instr.numInputs].map({
                        builder.type(of: $0)
                    })
                    let args = builder.randomVariables(ofTypes: argTypes)
                    builder.callFunction(f, withArgs: args, guard: op.isGuarded)

                case let op as CallMethod:
                    let m = op.methodName
                    let obj = builder.adopt(instr.input(0))
                    let argTypes = instr.inputs[1..<instr.numInputs].map({
                        builder.type(of: $0)
                    })
                    let args = builder.randomVariables(ofTypes: argTypes)
                    builder.callMethod(m, on: obj, withArgs: args, guard: op.isGuarded)

                default: // TODO: Support more instructions like CallFunctionWithSpread. See JsOperations.swift.
                    preconditionFailure("Unsupported type of function/method call: ")
            }
        }
    }
}


/// TODO: Add some more complicated mutators involving multiple rounds of JIT compilation, de-optimization, and re-compilation
