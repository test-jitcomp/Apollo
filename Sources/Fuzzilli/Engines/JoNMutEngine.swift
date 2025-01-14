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


/// The core fuzzer responsible for generating and executing programs with CSE/JoNM, specifically for JIT compilers.
///
/// More details are available in the SOSP'23 paper: Validating JIT Compilers via Compilation Space Exploration.
public class JoNMutEngine: FuzzEngine {
    // The number of consecutive mutations to apply to a sample.
    private let numConsecutiveMutations: Int

    // The mutator which helps add some checksum operations before applying JoN mutations
    private let chksumOpInserter = InsChksumOpsModestMutator()

    // The mutator, working as a backup, helps add a neutral loop into the program
    private let neuLoopInserter = PlainInsNeuLoopMutator()

    // The mutator, working as another backup, helps wraps a program by a function and calls it by a loop
    private let fuzzJitMutator = PlainFuzzJITMutator()

    public init(numConsecutiveMutations: Int) {
        self.numConsecutiveMutations = numConsecutiveMutations

        super.init(name: "JoNMutEngine")
    }

    /// Perform one round of fuzzing.
    ///
    /// High-level fuzzing algorithm:
    ///
    ///     seed = pickSampleFromCorpus(woJoN)
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
        let rawSeed = randomProgramForJoNMutating()

        guard let seed = preprocess(rawSeed) else {
            fatalError("Failed to inserting checksum variable into the program")
        }
        guard mayBeDeterministicExecutionStdout(seed, n: 3) else {
            return // The seed we've picked is either interesting or flaky
        }

        // Execute the seed program and obtain its input as our referee
        let seedExec = execute0(seed, withCaching: true)

        // Perform a sequence of JoN mutations and check their results
        for _ in 0..<(numConsecutiveMutations) {
            var mutator: Mutator = fuzzer.jonMutators.randomElement()

            let maxAttempts: Int = 5
            var mutantOrNil: Program? = nil
            for i in 0...maxAttempts {
                if i == maxAttempts {
                    // We failed too many times.
                    // Fallback to the simple mutator.
                    mutator = withEqualProbability({self.neuLoopInserter}, {self.fuzzJitMutator})
                }
                if let result = mutator.mutate(seed, for: fuzzer) {
                    // Success!
                    result.contributors.formUnion(seed.contributors)
                    mutator.addedInstructions(result.size - seed.size)
                    mutantOrNil = postprocess(result)
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

            // Execute the mutant and check its output aginst our referee
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
    private func preprocess(_ program: Program) -> Program? {
        // All interesting programs that have been added to the corpus are being minimized.
        // There're quite a few chances that our chksums are eliminated. Thus, we will always
        // be adding some new chksum updating operations for each seed program.
        return chksumOpInserter.mutate(
            chksumOpInserter.preprocess(program, for: fuzzer), for: fuzzer
        )
    }

    /// Post-processing of programs to facilitate JoN mutations on them.
    private func postprocess(_ program: Program) -> Program {
        return chksumOpInserter.postprocess(program, for: fuzzer)
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
