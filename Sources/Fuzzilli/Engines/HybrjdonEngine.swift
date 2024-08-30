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

/// This is a hybrid engine which interleaves JenerativeEngine, MutationEngine, and most importantly JoNMutEngine.
///
/// The purpose of this interleaving is two fold: First, we hope to improve the diversity of the generated program to
/// find more crashes, in which GenerativeEngine and MutationEngine show quite some handiness. On the other
/// hand, we aim to find some miscompilations which is the focus of JoN mutations where JenerativeEngine is helpful
/// to generate a bunch of more mutable samples for its mutation.
public class HybrjdonEngine: FuzzEngine {
    // The engines to hybrid/interleave in our mutation
    private let mutEngine: MutationEngine
    private let jenEngine: JenerativeEngine
    private let jonmEngine: JoNMutEngine
    private let engines: WeightedList<FuzzEngine>

    public init(
        numConsecutiveMutations: Int,
        numConsecutiveJenerations: Int,
        weightMutation: Int = 6,
        weightJeneration: Int = 2,
        weightJoNMutation: Int = 2
    ) {
        self.mutEngine = MutationEngine(numConsecutiveMutations: numConsecutiveMutations)
        self.jenEngine = JenerativeEngine(numConsecutiveJenerations: numConsecutiveJenerations)
        self.jonmEngine = JoNMutEngine(numConsecutiveMutations: numConsecutiveMutations)
        self.engines = WeightedList<FuzzEngine>([
            (mutEngine,           weightMutation),
            (jenEngine,           weightJeneration),
            (jonmEngine,          weightJoNMutation)
        ])

        super.init(name: "HybrjdonEngine")
    }

    override func initialize() {
        self.mutEngine.initialize(with: self.fuzzer)
        self.jenEngine.initialize(with: self.fuzzer)
        self.jonmEngine.initialize(with: self.fuzzer)
    }

    /// Perform one round of fuzzing.
    public override func fuzzOne(_ group: DispatchGroup) {
        let engine = self.engines.randomElement()
        engine.fuzzOne(group)
    }
}
