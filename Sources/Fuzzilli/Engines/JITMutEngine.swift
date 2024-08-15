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

    // Factor for continue selecting a JIT mutator again when one of them fails
    private static let ACCU_PROB_FACTOR = 0.75

    // The number of consecutive mutations to apply to a sample.
    private let numConsecutiveMutations: Int

    // The number of consecutive JIT mutations to apply to a sample.
    private let numConsecutiveJITMutations: Int

    // The probability of applying JIT mutations in the end
    private let probJITMutation: Double

    // Mutators to apply when all JIT mutations fail
    private let backupMutators: WeightedList<Mutator>

    public init(numConsecutiveMutations: Int, numConsecutiveJITMutations: Int, probJITMutation: Double) {
        self.numConsecutiveMutations = numConsecutiveMutations
        self.numConsecutiveJITMutations = numConsecutiveJITMutations
        self.probJITMutation = probJITMutation
        // TODO: May be add program template
        self.backupMutators = WeightedList<Mutator>([
            (CodeGenMutator(),               5),
            (SubrtJITCompMutator(),          1),
        ])

        super.init(name: "JITMutEngine")
    }

    /// Perform one round of fuzzing.
    ///
    /// High-level fuzzing algorithm:
    ///
    ///     let parent = pickSampleFromCorpus(woJIT)
    ///     repeat N times:
    ///         let current = if it is the Nth time mutation and prob <= JIT_PROB:
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
            var mutator: Mutator, maxAttempts: Int, accProbJITMut: Double
            if i < numConsecutiveMutations || !probability(self.probJITMutation) {
                mutator = fuzzer.mutators.randomElement()
                maxAttempts = 10
                accProbJITMut = 1.0
            } else {
                mutator = fuzzer.jitMutators.randomElement()
                maxAttempts = 5
                accProbJITMut = self.probJITMutation
            }

            var mutatedProgram: Program? = nil
            for j in 0...maxAttempts {
                if let result = mutator.mutate(parent, for: fuzzer) {
                    // Success!
                    result.contributors.formUnion(parent.contributors)
                    mutator.addedInstructions(result.size - parent.size)
                    mutatedProgram = result
                    break
                } else {
                    // Try a different mutator.
                    mutator.failedToGenerate()
                    if i < numConsecutiveMutations || !probability(accProbJITMut) { // We keep mutating the program by common mutators
                        mutator = fuzzer.mutators.randomElement()
                    } else if j < maxAttempts { // We keep mutating the program by JIT mutators
                        mutator = fuzzer.jitMutators.randomElement()
                        accProbJITMut = accProbJITMut * JITMutEngine.ACCU_PROB_FACTOR
                    } else { // We should apply JIT mutations but we are the last attempts, giving in.
                        mutator = backupMutators.randomElement()
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
