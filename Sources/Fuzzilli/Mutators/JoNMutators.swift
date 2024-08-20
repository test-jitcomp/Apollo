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
        forMutating program: Program? = nil,
        _ body: ((ProgramBuilder) -> ())? = nil
    ) -> Program {
        let b = fuzzer.makeBuilder(forMutating: program)
        if let bd = body {
            bd(b)
        } else {
            b.buildPrefix()
            b.build(n: defaultSmallCodeBlockSize)
        }
        return b.finalize()
    }
    
    /// Create a random neutral loop.
    ///
    /// Let's embed the neutral loop into a brand new, small program which has no
    /// connections to the program under mutation
    func randomNeutralLoop(forMutating program: Program) -> Program {
        return randomProgram(forMutating: program) { b in
            b.buildTryCatchFinally(tryBody: {
                b.buildPrefix()
                b.buildRepeatLoop(n: defaultMaxLoopTripCountInJIT) {
                    b.build(n: defaultSmallCodeBlockSize / 2, by: .generating)
                }
            }, catchBody: { _ in
                // We dismiss the exception to avoid any unexpected behaviors
                return
            })
        }
    }
}

/// A JoN mutator is basically a subroutine mutator
public class JoNMutator: SubroutineMutator {
    var contextAnalyzer = ContextAnalyzer()
    
    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        contextAnalyzer = ContextAnalyzer()
    }
    
    final public override func canMutate(_ s: Instruction?, _ i: Instruction) -> Bool {
        contextAnalyzer.analyze(i)
        return (
            // It's wired that some instructions are not in the .javascript context
            // (removing this condition check may cause assertion failures...)
            contextAnalyzer.context.contains(.javascript) &&
            // We cannot within a loop; otherwise, we might never stop...
            !contextAnalyzer.context.contains(.loop) &&
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

/// A JoN mutator that inserts a neutral loop into a random program point of a subroutine
public class InsNeuLoopMutator: JoNMutator {
    var program: Program? = nil
    
    public override func beginMutation(of p: Program, using b: ProgramBuilder) {
        super.beginMutation(of: p, using: b)
        program = p
    }
    
    override func canMutateSubroutine(_ s: Instruction?, _ i: Instruction) -> Bool {
        return s != nil // We can mutate any subroutines
    }
    
    override public func mutate(_ subrt: [Instruction], _ mutable: [Bool], _ b: ProgramBuilder) {
        // We can only insert our loop before instructions that are mutable
        let insertAt = chooseUniform(from: (1..<subrt.count).filter({ mutable[$0] }))
        for (index, instr) in subrt.enumerated() {
            if index == insertAt {
                b.append(b.randomNeutralLoop(forMutating: program!))
            }
            b.adopt(instr)
        }
    }
}
