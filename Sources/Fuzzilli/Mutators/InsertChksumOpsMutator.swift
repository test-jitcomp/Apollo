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

    /// Finds the class definition (i.e., BeginClassDefinition) for an instruction
    public func findClassDefinition(for instr: Instruction) -> Instruction {
        var index = instr.index
        while index >= 0 {
            let curr = self[index]
            if curr.isBlockStart && curr.op is BeginClassDefinition {
                return curr
            }
            index -= 1
        }
        fatalError("Cannot reach here")
    }

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
            Self.isLoadChksumContainer(program.code[$0])
        }
        guard loadInstrIndices.count > 0 else {
            return program // No LoadNamedVariable(chksumContainer)s at all.
        }

        let b = fuzzer.makeBuilder(forMutating: program)

        b.adopting(from: program) {
            for instr in program.code {
                if Self.isLoadChksumContainer(instr) {
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

        let chksumCont = Self.loadChksumContainer(using: builder)
        builder.hide(chksumCont)  // Hide it to avoid being used by our builder
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
            Self.isLoadChksumContainer(program.code[$0])
        }
        guard loadInstrIndices.count > 1 && loadInstrIndices[0] == 0 else {
            return program // Either no additional LoadNamedVariable(chksumContainer)s (count == 0),
            // or the program is not from us ([0] != 0),
            // or the program only from us (count == 1 && [0] == 0).
            // In either cases, we directly return.
        }

        let b = fuzzer.makeBuilder(forMutating: program)

        // We keep only the very first one and replace all others
        b.adopting(from: program) {
            for (index, instr) in program.code.enumerated() {
                if index == 0 || !Self.isLoadChksumContainer(instr) {
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

    /// Get the checksum value
    public static func getChksumValue(in container: Variable, using b: ProgramBuilder) -> Variable {
        let chksumIndex = Int64(JavaScriptCompatLifter.chksumIndexInContainer)
        return b.getElement(chksumIndex, of: container)
    }

    /// Update the checksum by a value with a random operator
    public static func updateChksumValue(in container: Variable, using b: ProgramBuilder, by updates: Variable) {
        let chksumIndex = Int64(JavaScriptCompatLifter.chksumIndexInContainer)
        b.updateElement(
            chksumIndex,
            of: container,
            with: updates,
            using: withEqualProbability(
                {.Add}, {.Sub}, {.Mul}, // Discard .Div and .Mod to avoid DivByZero
                {.BitAnd}, {.BitOr}, {.Xor},
                {.LogicOr}, {.LogicAnd},
                {.LShift}, {.RShift}, {.UnRShift}
            )
        )
    }

    /// Set the checksum to a specific value
    public static func setChksumValue(in container: Variable, using b: ProgramBuilder, to value: Variable) {
        let chksumIndex = Int64(JavaScriptCompatLifter.chksumIndexInContainer)
        b.setElement(chksumIndex, of: container, to: value)
    }

    /// Get a subroutine's checksum update count for a subrt
    public static func getUpdateCount(in container: Variable, using b: ProgramBuilder, for subrtKey: Variable) -> Variable {
        let counterIndex = Int64(JavaScriptCompatLifter.chksumCounterIndexInContainer)
        let counterMap = b.getElement(counterIndex, of: container)
        return b.getComputedProperty(subrtKey, of: counterMap)
    }

    /// Set a subroutine's checksum update count for a subrt
    public static func setUpdateCount(in container: Variable, using b: ProgramBuilder, for subrtKey: Variable, to count: Variable) {
        let counterIndex = Int64(JavaScriptCompatLifter.chksumCounterIndexInContainer)
        let counterMap = b.getElement(counterIndex, of: container)
        b.setComputedProperty(subrtKey, of: counterMap, to: count)
    }

    /// Check if an instruction is the instruction for loading checksum container
    public static func isLoadChksumContainer(_ i: Instruction) -> Bool {
        if let op = i.op as? LoadNamedVariable, (
            op.variableName == JavaScriptCompatLifter.chksumContainerName
        ) {
            return true
        } else {
            return false
        }
    }

    /// Load and return the chksum container
    public static func loadChksumContainer(using b: ProgramBuilder) -> Variable {
        return b.loadNamedVariable(JavaScriptCompatLifter.chksumContainerName)
    }

    /// Reset the checksum container
    public static func resetChksumContainer(_ container: Variable, using b: ProgramBuilder) {
        let chksumIndex = Int64(JavaScriptCompatLifter.chksumIndexInContainer)
        let counterIndex = Int64(JavaScriptCompatLifter.chksumCounterIndexInContainer)
        b.setElement(chksumIndex, of: container, to: b.loadInt(0xAB0110))
        b.setElement(counterIndex, of: container, to: b.createObject(with: [:]))
    }
}


/// An inserter that inserts chksum update operations all over the program.
public class InsChksumOpsAggressiveMutator: InsertChksumOpMutator {

    override func insertChksumOps(in c: Variable, after i: Instruction, using b: ProgramBuilder) {
        guard (
            probability(probaInsertion) &&
            // As long as we are in a JavaScript context, we can insert chksum ops
            contextAnalyzer.context.contains(.javascript)
        ) else {
            return
        }
        Self.updateChksumValue(in: c, using: b, by: b.loadInt(Int64.random(in: 1...25536)))
    }
}

/// An inserter that inserts chksum update operations only outside of any subroutine.
public class InsChksumOpsConservativeMutator: InsertChksumOpMutator {

    override func insertChksumOps(in c: Variable, after i: Instruction, using b: ProgramBuilder) {
        guard (
            probability(probaInsertion) &&
            // As long as we are in a JavaScript context, we can insert chksum ops
            contextAnalyzer.context.contains(.javascript) &&
            // We do not prefer subroutines as when the subroutine is used
            // as like an argument of other subroutines, it may introduce
            // unexpected behaviors. For example, the stack size is different
            // in different engines, a stack overflow may generate unequal
            // number of chksum updates at runtime, causing the final chksum
            // value to be different in different engines; this is bad
            // for differential testing, especially for miscompilation bugs.
            !contextAnalyzer.aggregrateContext.contains(.subroutine)
        ) else {
            return
        }
        Self.updateChksumValue(in: c, using: b, by: b.loadInt(Int64.random(in: 1...25536)))
    }
}

/// An inserter that inserts chksum update operations modestly. In particular:
/// - Outside of subroutines, chksum update operations are inserted casually.
/// - Inside of subroutines, the number chksum updates are bounded to a limit.
public class InsChksumOpsModestMutator: InsertChksumOpMutator {

    // The program being inserting checksum update operations
    var program = Program()

    // We associate the chksum update count with each subroutine.
    // ensuring that the updates for each one is bound to a limit.
    var subrtKeyMap = [Int:String]()

    // The function to update checksum update operations
    var chksumUpdate = Variable(number: 0)

    // We use the def-use relations to distinguish different subroutines
    var defUseAnalyzer = DefUseAnalyzer(for: Program())

    override func beginInsertion(in c: Variable, for p: Program, using b: ProgramBuilder) {
        program = p
        subrtKeyMap = [Int:String]()
        defUseAnalyzer = DefUseAnalyzer(for: p)
        defUseAnalyzer.analyze()
        chksumUpdate = buildUpdateChksumFunction(for: c, using: b)
        b.hide(chksumUpdate) // Hide it to avoid being used
    }

    override func insertChksumOps(in c: Variable, after i: Instruction, using b: ProgramBuilder) {
        if i.op is BeginAnySubroutine && subrtKeyMap[i.index] == nil {
            // Each subroutine is given a unique key for requesting chksum updates
            subrtKeyMap[i.index] = "s\(subrtKeyMap.count)"
        }

        guard (
            probability(probaInsertion) &&
            contextAnalyzer.context.contains(.javascript)
        ) else {
            return
        }

        var subrtKey: String? = nil
        if !contextAnalyzer.aggregrateContext.contains(.subroutine) {
            // We directly apply the updates as we are not in a subroutine
            subrtKey = "global"
        } else {
            // We apply different strategies for different subroutines
            let subrt = program.code.findSubrtineDefinition(for: i)
            switch subrt.op {
            // Plain functions: we check their uses and stay away from them if they are used as arguments
            case is BeginPlainFunction, is BeginArrowFunction, is BeginGeneratorFunction:
                subrtKey = getSubrtKeyOf(func: subrt)

            // Async functions: we stay away (the orders of their execution are underdetermined)
            case is BeginAsyncFunction, is BeginAsyncArrowFunction, is BeginAsyncGeneratorFunction:
                subrtKey = nil

            // Constructor functions: we accept it
            case is BeginConstructor:
                subrtKey = getSubrtKeyOf(func: subrt)

            // Object methods: we stay away from builtin methods
            case let op as BeginObjectLiteralMethod:
                subrtKey = getSubrtKeyOf(method: op.methodName, withDifinition: subrt)

            // Object getter/setter methods: we accept them
            case is BeginObjectLiteralGetter, is BeginObjectLiteralSetter:
                subrtKey = subrtKeyMap[subrt.index]!

            // Object computed methods: we stay away (it's difficult to determine the [Symbol] of the method)
            case is BeginObjectLiteralComputedMethod:
                subrtKey = nil

            // Class constructor methods: we stay away as Fuzzilli typically generates "class C extends f {}; new C(f); ..."
            case is BeginClassConstructor:
                subrtKey = nil

            // Class methods: we stay away from builtin methods
            case let op as BeginClassInstanceMethod:
                subrtKey = getSubrtKeyOf(method: op.methodName, withDifinition: subrt)

            // Class private methods: we stay away from builtin methods
            case let op as BeginClassPrivateInstanceMethod:
                subrtKey = getSubrtKeyOf(method: op.methodName, withDifinition: subrt)

            // Class getter/setter methods: we accept them
            case is BeginClassInstanceGetter, is BeginClassInstanceSetter:
                subrtKey = subrtKeyMap[subrt.index]!

            // Class static initializer: we accept them
            case is BeginClassStaticInitializer:
                subrtKey = subrtKeyMap[subrt.index]!

            // Class static methods: we stay away from builtin methods
            case let op as BeginClassStaticMethod:
                subrtKey = getSubrtKeyOf(method: op.methodName, withDifinition: subrt)

            // Class static private methods: we stay away from builtin methods
            case let op as BeginClassPrivateStaticMethod:
                subrtKey = getSubrtKeyOf(method: op.methodName, withDifinition: subrt)

            // Class static getter/setter methods: we accept them
            case is BeginClassStaticGetter, is BeginClassStaticSetter:
                subrtKey = subrtKeyMap[subrt.index]!

            default:
                subrtKey = nil
            }
        }

        if let subrtKey = subrtKey {
            b.callFunction(chksumUpdate, withArgs: [
                b.loadString(subrtKey),
                b.loadInt(Int64.random(in: 1...25536))
            ])
        }
    }

    private func buildUpdateChksumFunction(for container: Variable, using b: ProgramBuilder) -> Variable {
        return b.buildPlainFunction(with: .parameters(.string, .integer)) { args in
            let subrtKey = args[0]
            let updates = args[1]

            // Check if we're called by a subroutine
            b.buildIf(b.compare(subrtKey, with: b.loadString("global"), using: .equal)) {
                // We're not. Directly update the checksum.
                Self.updateChksumValue(in: container, using: b, by: updates)
                b.doReturn()
            }

            // Load the chksum updates counter map
            let updateCount = Self.getUpdateCount(in: container, using: b, for: subrtKey)

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
                Self.updateChksumValue(in: container, using: b, by: updates)
                Self.setUpdateCount(in: container, using: b, for: subrtKey, to: b.binary(updateCount, b.loadInt(1), with: .Add))
            }
        }
    }

    private func getSubrtKeyOf(method: String, withDifinition subrt: Instruction) -> String? {
        if ["toString", "valueOf"].contains(method) {
            return nil
        } else {
            return subrtKeyMap[subrt.index]!
        }
    }

    private func getSubrtKeyOf(func subrt: Instruction) -> String? {
        let s = subrt.output
        // We expect s not to be used as a higher-order function as in such
        // cases the Fuzzilli-generated code typically cause stack overflow,
        // making our chksums (even though we have set a limit) unstable.
        for use in defUseAnalyzer.uses(of: s) {
            guard use.isCall && use.hasInputs && use.inputs[0] == s else {
                return nil // The subrt s is likely to be used higherly-order
            }
            // The subrt s is the callee, let's check if it also one of the arguments
            for i in 1..<use.inputs.count {
                if use.inputs[i] == s {
                    return nil // The subrt s is passed as a higher-order argument
                }
            }
        }
        return subrtKeyMap[subrt.index]!
    }
}
