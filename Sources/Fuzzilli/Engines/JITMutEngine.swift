// Copyright 2019 Google LLC
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

/// The core fuzzer responsible for generating and executing programs, specifically for JIT compilers.
public class JITMutEngine: FuzzEngine {
    // The number of consecutive mutations to apply to a sample.
    private let numConsecutiveMutations: Int

    // The number of consecutive JIT mutations to apply to a sample.
    private let numConsecutiveJITMutations: Int

    public init(numConsecutiveMutations: Int, numConsecutiveJITMutations: Int) {
        self.numConsecutiveMutations = numConsecutiveMutations
        self.numConsecutiveJITMutations = numConsecutiveJITMutations

        super.init(name: "JITMutEngine")
    }

    /// Perform one round of fuzzing.
    ///
    /// High-level fuzzing algorithm:
    ///
    ///     let parent = pickSampleFromCorpus(woJIT)
    ///     repeat N times:
    ///         let current = if it is the Nth time mutation: 
    ///             jit-mutate(parent)
    ///         else
    ///             mutate(parent) 
    ///         execute(current)
    ///         if current produced crashed:
    ///             output current
    ///         elif current resulted in a runtime exception or a time out:
    ///             // do nothing
    ///         elif current produced new, interesting behaviour:
    ///             minimize and add to corpus
    ///         else
    ///             parent = current
    ///
    ///
    /// This ensures that samples will be mutated multiple times as long
    /// as the intermediate results do not cause a runtime exception.
    public override func fuzzOne(_ group: DispatchGroup) {
        var parent = randomProgramForJITMutating()
        parent = prepareForMutating(parent)
        for i in 0..<(numConsecutiveMutations + numConsecutiveJITMutations) {
            // TODO: factor out code shared with the MutationEngine/HybridEngine?
            var mutator: Mutator 
            if i < numConsecutiveMutations {
                mutator = fuzzer.mutators.randomElement()
            } else {
                mutator = fuzzer.jitMutators.randomElement()
            }

            let maxAttempts: Int = 10
            var mutatedProgram: Program? = nil
            for _ in 0..<maxAttempts {
                if let result = mutator.mutate(parent, for: fuzzer) {
                    // Success!
                    result.contributors.formUnion(parent.contributors)
                    mutator.addedInstructions(result.size - parent.size)
                    mutatedProgram = result
                    break
                } else {
                    // Try a different mutator.
                    mutator.failedToGenerate()
                    if i < numConsecutiveMutations {
                        mutator = fuzzer.mutators.randomElement()
                    } else {
                        mutator = fuzzer.jitMutators.randomElement()
                    }
                }
            }

            guard let program = mutatedProgram else {
                logger.warning("Could not mutate sample, giving up. Sample:\n\(FuzzILLifter().lift(parent))")
                continue
            }

            assert(program !== parent)
            let outcome = execute(program)

            // Mutate the program further if it succeeded.
            if .succeeded == outcome {
                parent = program
            }
        }
    }

    /// Pre-processing of programs to facilitate mutations on them.
    private func prepareForMutating(_ program: Program) -> Program {
        let b = fuzzer.makeBuilder()
        b.buildPrefix()
        b.append(program)
        return b.finalize()
    }

    /// Return a program (without JIT mutations) for JIT mutation
    private func randomProgramForJITMutating() -> Program {
        var prog = fuzzer.corpus.randomElementForMutating()
        while isFromJITMutators(prog) {
            prog = fuzzer.corpus.randomElementForMutating()
        }
        return prog
    }

    /// Check if the program is mutated by one of the JIT mutators
    private func isFromJITMutators(_ program: Program) -> Bool {
        return !fuzzer.jitMutators.filter({ program.contributors.contains($0) }).isEmpty
    }
}
