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

extension Code {
    /// Find and return all subroutines.
    ///
    /// The returned list will be ordered:
    ///  - an inner subroutine will come before its surrounding subroutine
    ///  - a subroutine ending before another subroutine starts will come before that subroutine
    public func findAllSubroutines() -> [BlockGroup] {
        return self.findAllBlockGroups().filter({ bg in
            self[bg.head].op is BeginAnySubroutine && self[bg.tail].op is EndAnySubroutine
        })
    }
    
    /// FInd and return all subroutines at a specific depth.
    ///
    /// The returned list will be ordered:
    ///  - a subroutine ending before subroutine block starts will come before that subroutine
    public func findAllSubroutines(at depth: Int) -> [BlockGroup] {
        return self.findAllBlockGroups(at: depth).filter({ bg in
            self[bg.head].op is BeginAnySubroutine && self[bg.tail].op is EndAnySubroutine
        })
    }
}

/// Base class for mutators that operate on an outmost subroutine (function, method, etc.)
public class SubroutineMutator: Mutator {
    let maxSimultaneousMutations: Int
    
    public init(name: String? = nil, maxSimultaneousMutations: Int = 1) {
        self.maxSimultaneousMutations = maxSimultaneousMutations
        super.init(name: name)
    }
    
    public override func mutate(_ program: Program, using b: ProgramBuilder, for fuzzer: Fuzzer) -> Program? {
        beginMutation(of: program, using: b)
        
        let allSubrts: [Block] = program.code.findAllSubroutines(at: 0).map{
            Block(head: $0.head, tail: $0.tail, in: program.code)
        }
        
        var candidates: [Block] = []
        
        // Select those subroutines that can be mutated. We will iterate all instructions
        // in the program and save subroutines of which one instruction is mutable
        var subrtStartInstr: Instruction? = nil, subrtIndex: Int = 0
        for (index, instr) in program.code.enumerated() {
            if subrtIndex < allSubrts.count && index == allSubrts[subrtIndex].head {
                subrtStartInstr = instr
            }
            
            // We save a subroutines as a candidate if any of its instruction is mutable
            if canMutate(subrtStartInstr, instr), let startInstr = subrtStartInstr {
                if (
                    candidates.isEmpty ||
                    candidates.last?.head != startInstr.index
                ) {
                    candidates.append(allSubrts[subrtIndex])
                }
            }
            
            if subrtIndex < allSubrts.count && index == allSubrts[subrtIndex].tail {
                subrtIndex += 1
                subrtStartInstr = nil
            }
        }
        
        guard candidates.count > 0 else {
            return nil
        }
        
        // Select some subroutines for mutation
        var toMutateIndices = Set<Int>()
        for _ in 0..<Int.random(in: 1...maxSimultaneousMutations) {
            toMutateIndices.insert(chooseUniform(from: Array(0..<candidates.count)))
        }
        
        var toMutateSubrts = [Block]()
        for (index, group) in candidates.enumerated() {
            if toMutateIndices.contains(index) {
                toMutateSubrts.append(group)
            }
        }
        
        // Apply mutations: either mutate the subroutine, or append an instruction
        b.adopting(from: program) {
            var index = 0, toMutateIndex = 0
            while index < program.size {
                let instr = program.code[index]
                if toMutateIndex < toMutateSubrts.count && index == toMutateSubrts[toMutateIndex].head {
                    let subrtInstrs = [Instruction](program.code[toMutateSubrts[toMutateIndex]])
                    mutate(subrtInstrs, b)
                    index = toMutateSubrts[toMutateIndex].tail + 1
                    toMutateIndex += 1
                } else {
                    b.adopt(instr)
                    index += 1
                }
            }
        }
        
        endMutation(of: program, using: b)
        
        return b.finalize()
    }
    
    /// Can be overwritten by child classes.
    public func beginMutation(of program: Program, using builder: ProgramBuilder) {}
    
    /// Can be overwritten by child classes.
    public func endMutation(of program: Program, using builder: ProgramBuilder) {}
    
    /// Overridden by child classes.
    /// Check if the subroutine, specifically at the instruction, can be mutated by the mutator.
    /// The method will be iterated over all instructions of a program, regardless of if the subroutine of an instruction was already considered mutable.
    public func canMutate(_ subrt: Instruction?, _ instr: Instruction) -> Bool {
        fatalError("This method must be overriden")
    }
    
    /// Overridden by child classes.
    /// Mutate a single subroutine
    public func mutate(_ subrt: [Instruction], _ builder: ProgramBuilder) {
        fatalError("This method must be overridden")
    }
}
