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


/// A mutator which assists JoN mutation by inserting a checksum variable into a program.
fileprivate class InsertChksumMutator: Mutator {

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
            // "console.log(`Checksum: ${checkSumContainer[0]}`)"
            b.callMethod(
                "log",
                on: b.loadBuiltin("console"),
                withArgs: [
                    b.binary(
                        b.loadString("Checksum: "),
                        b.getElement(0, of: chkSumContainer),
                        with: .Add
                    )
                ]
            )
        })

        return b.finalize()
    }
}

/// The core fuzzer responsible for generating and executing programs with CSE/JoNM, specifically for JIT compilers.
///
/// More details are available in the SOSP'23 paper: Validating JIT Compilers via Compilation Space Exploration.
public class JoNMutEngine: FuzzEngine {
    // The number of consecutive mutations to apply to a sample.
    private let numConsecutiveMutations: Int

    // The mutator which helps add a checksum before applying JoN mutations
    private let chksumInserter = InsertChksumMutator()

    public init(numConsecutiveMutations: Int, probGenNew: Double) {
        self.numConsecutiveMutations = numConsecutiveMutations

        super.init(name: "JoNMutEngine")
    }

    /// Perform one round of fuzzing.
    ///
    /// High-level fuzzing algorithm:
    ///
    ///     seed = pickSampleFromCorpus(woJIT)
    ///     seed_out = execute(seed)
    ///     repeat N times:
    ///         mutant = jon-mutate(seed)
    ///         execute(mutant)
    ///         if mutant produced crashed or mutant_out != seed_out:
    ///             output mutant
    ///         elif current resulted in a runtime exception or a time out:
    ///             // do nothing
    ///         elif current produced new, interesting behavior:
    ///             minimize and add to corpus
    ///
    /// This ensures that samples will be mutated multiple times as long
    /// as the intermediate results do not cause a runtime exception.
    public override func fuzzOne(_ group: DispatchGroup) {
        // TODO: Are there any random behaviors in seed generation? Perhaps removing all randomXxx builtins?
        let rawSeed = randomProgramForJoNMutating()

        guard let seed = prepareForJoNMutating(rawSeed) else {
            fatalError("Failed to inserting checksum variable into the program")
        }

        // Execute the seed program
        let seedExec = execute0(seed, withCaching: true)
        if seedExec.outcome != .succeeded {
            return // We accidentally picked an interesting program
        }

        // Perform a sequence of JoN mutations and check their results
        for _ in 0..<(numConsecutiveMutations) {
            var mutator = fuzzer.jonMutators.randomElement()

            let maxAttempts: Int = 5
            var mutantOrNil: Program? = nil
            for _ in 0..<maxAttempts {
                if let result = mutator.mutate(seed, for: fuzzer) {
                    // Success!
                    result.contributors.formUnion(seed.contributors)
                    mutator.addedInstructions(result.size - seed.size)
                    mutantOrNil = result
                    break
                } else {
                    // Try a different mutator.
                    mutator.failedToGenerate()
                    mutator = fuzzer.jonMutators.randomElement()
                }
            }

            // TODO: Perhaps generate a new program for JoN mutation?
            guard let mutant = mutantOrNil else {
                logger.warning("Could not mutate sample, giving up. Sample:\n\(FuzzILLifter().lift(seed))")
                continue
            }

            assert(mutant !== seed)

            let mutantExec = execute0(mutant, withCaching: true)

            // The mutant program exit succeededly while with different results
            // TODO: Develop a ProgramEvaluator to evaluate miscompilation and generate Aspects
            if mutantExec.outcome == .succeeded && mutantExec.stdout != seedExec.stdout {
                fuzzer.processMiscompilation(
                    mutant, withStdout: mutantExec.stdout,
                    withReferee: seed, withRefereeStdout: seedExec.stdout,
                    origin: .local,
                    withExectime: mutantExec.execTime
                )
                mutant.contributors.generatedMiscompilingSample()
            }
        }
    }

    /// Pre-processing of programs to facilitate JoN mutations on them.
    ///
    /// Specifically, to prevent that the program does not print, we manually
    /// insert a checksum variable into it and print its value in the end.
    private func prepareForJoNMutating(_ program: Program) -> Program? {
        return chksumInserter.mutate(program, for: fuzzer)!
    }

    /// Pick a program (without JoN mutations) for JoN mutation
    private func randomProgramForJoNMutating() -> Program {
        var prog = fuzzer.corpus.randomElementForMutating()
        while isFromJoNMutators(prog) {
            prog = fuzzer.corpus.randomElementForMutating()
        }
        return prog
    }

    /// Check if the program is mutated by one of the JIT mutators
    private func isFromJoNMutators(_ program: Program) -> Bool {
        return !fuzzer.jonMutators.filter({ program.contributors.contains($0) }).isEmpty
    }
}
