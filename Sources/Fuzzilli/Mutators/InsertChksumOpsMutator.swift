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

    /// Finds the subroutine definition (i.e., BeginAnySubroutine) for an instruction
    public func findSubrtineDefinition(for instr: Instruction) -> Instruction {
        var index = instr.index
        while index >= 0 {
            let curr = self[index]
            if curr.isBlockStart && curr.op is BeginAnySubroutine {
                return curr
            }
            index -= 1
        }
        fatalError("Cannot reach here")
    }
}

/// A mutator which inserts checksums into a program to facilitate the discovery of miscompilation bugs.
///
///     prog
///
///      v
///
///     chksum = 0xAB0110;
///     try {
///        prog's instrs and ops to chksum
///     } finally {
///       print(chksum)
///     }
///
/// The program is unrolled with some operations to chksum are inserted.
/// The try-finally block (embeded in our compat lifter) ensures that the chksum are always output.
public class InsertChksumOpMutator: Mutator {

    public static let maxNumberOfUpdatesPerSubrt: Int = 50

    // The probability of inserting a chksum update operation at a program point
    let probaInsertion: Double

    // The analyzer which analyzes the context after an instruction
    var contextAnalyzer = ContextAnalyzer()

    public init(name: String? = nil, probaInsertion: Double = 0.2) {
        self.probaInsertion = probaInsertion
        super.init(name: name)
    }

    /// Preprocess to remove all checksum loading instructions from any program.
    ///
    /// This method exists as the default behavior of ProgramBuilder is .generatingAndSplicing which
    /// splices code from other programs in the corpus. There're chances that the spliced code are
    /// from us, containing code to load checksums and may further containing checksum updating code.
    /// This is unexpected for JoN mutations; we'll remove them all.
    ///
    /// Warning: Please avoid using this method to Programs generated by us !!!
    public func preprocess(_ program: Program, for fuzzer: Fuzzer) -> Program {
        let loadInstrIndices = program.code.indices.filter {
            isLoadChksumContainer(program.code[$0])
        }
        guard loadInstrIndices.count > 0 else {
            return program // No LoadNamedVariable(chksumContainer)s at all.
        }

        let b = fuzzer.makeBuilder()

        b.adopting(from: program) {
            for instr in program.code {
                if isLoadChksumContainer(instr) {
                    // We replace all "LoadNamedVariable chksum" with an new array
                    let output = b.adoptAndDefine(for: instr.output)
                    b.reassign(output, from: b.createArray(with: [
                        b.loadInt(0), b.buildObjectLiteral{ _ in }
                    ]))
                } else {
                    b.adopt(instr)
                }
            }
        }

        return b.finalize()
    }

    override func mutate(_ program: Program, using builder: ProgramBuilder, for fuzzer: Fuzzer) -> Program? {
        contextAnalyzer = ContextAnalyzer()

        let chksumCont = loadChksumContainer(using: builder)
        beginInsertion(in: chksumCont, for: program, using: builder)
        builder.adopting(from: program) {
            for instr in program.code {
                contextAnalyzer.analyze(instr)
                builder.adopt(instr)
                insertChksumOps(in: chksumCont, after: instr, using: builder)
            }
        }
        endInsertion(in: chksumCont, for: program, using: builder)

        return builder.finalize()
    }

    /// Postprocess to remove all, except the very first, unexpected checksum loading code from a program.
    ///
    /// Warning: Call this method after calling Self.preprocess() and Self.mutate().
    public func postprocess(_ program: Program, for fuzzer: Fuzzer) -> Program {
        let loadInstrIndices = program.code.indices.filter {
            isLoadChksumContainer(program.code[$0])
        }
        guard loadInstrIndices.count > 0 && loadInstrIndices[0] == 0 else {
            return program // Either no additional LoadNamedVariable(chksumContainer)s,
            // or the program is not from us. In either case, we directly return.
        }

        let b = fuzzer.makeBuilder()

        // We keep only the very first one and replace all others
        b.adopting(from: program) {
            for (index, instr) in program.code.enumerated() {
                if index == 0 || !isLoadChksumContainer(instr) {
                    b.adopt(instr)
                } else {
                    // We replace it with an new array
                    let output = b.adoptAndDefine(for: instr.output)
                    b.reassign(output, from: b.createArray(with: [
                        b.loadInt(0), b.buildObjectLiteral{ _ in }
                    ]))
                }
            }
        }

        return b.finalize()
    }

    /// Can be overwritten by child classes.
    func beginInsertion(in container: Variable, for program: Program, using builder: ProgramBuilder) {}

    /// Can be overwritten by child classes.
    func endInsertion(in container: Variable, for program: Program, using builder: ProgramBuilder) {}

    /// Overridden by child classes.
    func insertChksumOps(in container: Variable, after instr: Instruction, using builder: ProgramBuilder) {
        fatalError("This method must be overridden")
    }

    func updateChksumValue(in chkSumContainer: Variable, using b: ProgramBuilder, by updates: Variable) {
        let chksumIndex = Int64(JavaScriptCompatLifter.chksumIndexInContainer)
        b.updateElement(
            chksumIndex,
            of: chkSumContainer,
            with: updates,
            using: withEqualProbability(
                {.Add}, {.Sub}, {.Mul}, // Discard .Div and .Mod to avoid DivByZero
                {.BitAnd}, {.BitOr}, {.Xor},
                {.LogicOr}, {.LogicAnd},
                {.LShift}, {.RShift}, {.UnRShift}
            )
        )
    }

    private func isLoadChksumContainer(_ i: Instruction) -> Bool {
        if let op = i.op as? LoadNamedVariable, (
            op.variableName == JavaScriptCompatLifter.chksumContainerName
        ) {
            return true
        } else {
            return false
        }
    }

    private func loadChksumContainer(using b: ProgramBuilder) -> Variable {
        return b.loadNamedVariable(JavaScriptCompatLifter.chksumContainerName)
    }
}


/// An inserter that inserts chksum update operations all over the program.
public class InsChksumOpsAggressiveMutator: InsertChksumOpMutator {

    override func insertChksumOps(in c: Variable, after i: Instruction, using b: ProgramBuilder) {
        guard (
            probability(probaInsertion) &&
            // As long as we are in a JavaScript context, we can insert chksum ops
            contextAnalyzer.aggregrateContext.contains(.javascript)
        ) else {
            return
        }
        updateChksumValue(in: c, using: b, by: b.loadInt(Int64.random(in: 1...25536)))
    }
}

/// An inserter that inserts chksum update operations only outside of any subroutine.
public class InsChksumOpsConservativeMutator: InsertChksumOpMutator {

    override func insertChksumOps(in c: Variable, after i: Instruction, using b: ProgramBuilder) {
        let context = contextAnalyzer.aggregrateContext
        guard (
            probability(probaInsertion) &&
            context.contains(.javascript) &&
            // We do not prefer subroutines as when the subroutine is used
            // as like an argument of other subroutines, it may introduce
            // unexpected behaviors. For example, the stack size is different
            // in different engines, a stack overflow may generate unequal
            // number of chksum updates at runtime, causing the final chksum
            // value to be different in different engines; this is bad
            // for differential testing, especially for miscompilation bugs.
            !context.contains(.subroutine)
        ) else {
            return
        }
        updateChksumValue(in: c, using: b, by: b.loadInt(Int64.random(in: 1...25536)))
    }
}

/// An inserter that inserts chksum update operations modestly. In particular:
/// - Outside of subroutines, chksum update operations are inserted casually.
/// - Inside of subroutines, the number chksum updates are bounded to a limit.
public class InsChksumOpsModestMutator: InsertChksumOpMutator {

    // The program being inserting checksum update operations
    var program: Program = Program()

    // We associate the chksum update count with each subroutine.
    // ensuring that the updates for each one is bound to a limit.
    var subrtKeyMap = [Int:String]()

    // The function to update checksum update operations
    var chksumUpdate: Variable = Variable(number: 0)

    override func beginInsertion(in c: Variable, for p: Program, using b: ProgramBuilder) {
        program = p
        subrtKeyMap = [Int:String]()
        chksumUpdate = buildUpdateChksumFunction(for: c, using: b)
    }

    override func insertChksumOps(in c: Variable, after i: Instruction, using b: ProgramBuilder) {
        if i.op is BeginAnySubroutine && subrtKeyMap[i.index] == nil {
            subrtKeyMap[i.index] = "s\(subrtKeyMap.count)"
        }

        let context = contextAnalyzer.aggregrateContext
        guard (
            probability(probaInsertion) &&
            context.contains(.javascript)
        ) else {
            return
        }

        let subrtKey: String
        if context.contains(.subroutine) {
            let subrt = program.code.findSubrtineDefinition(for: i)
            subrtKey = subrtKeyMap[subrt.index]!
        } else {
            subrtKey = "global"
        }

        b.callFunction(chksumUpdate, withArgs: [
            b.loadString(subrtKey),
            b.loadInt(Int64.random(in: 1...25536))
        ])
    }

    private func buildUpdateChksumFunction(for container: Variable, using b: ProgramBuilder) -> Variable {
        return b.buildPlainFunction(with: .parameters(.string, .integer)) { args in
            let subrtKey = args[0]
            let updates = args[1]

            // Check if we're called by a subroutine
            b.buildIf(b.compare(subrtKey, with: b.loadString("global"), using: .equal)) {
                // We're not. Directly update the checksum.
                updateChksumValue(in: container, using: b, by: updates)
                b.doReturn()
            }

            // Load the chksum updates counter map
            let cntrIndex = Int64(JavaScriptCompatLifter.chksumCounterIndexInContainer)
            let cntrMap = b.getElement(cntrIndex, of: container)

            let updateCount = b.getComputedProperty(subrtKey, of: cntrMap)

            // Check if this subroutine has ever been accessed
            b.buildIf(b.compare(updateCount, with: b.loadUndefined(), using: .equal)) {
                // Never accessed, our update count is zero
                b.reassign(b.loadInt(0), to: updateCount)
            }

            // Check if the chksum updates have reach the limit
            b.buildIf(b.compare(
                updateCount,
                with: b.loadInt(Int64(Self.maxNumberOfUpdatesPerSubrt)),
                using: .lessThan
            )) {
                // We're okay, let's update the chksum
                updateChksumValue(in: container, using: b, by: updates)
                b.setComputedProperty(subrtKey, of: cntrMap, to: b.binary(updateCount, b.loadInt(1), with: .Add))
            }
        }
    }
}
