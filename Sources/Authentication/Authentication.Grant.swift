extension Authentication {

    /// What a session records about how it was made: the proofs, so that a sensitive action can ask for a fresh
    /// one (step-up).
    public struct Grant: Sendable, Hashable {

        /// Every factor passed for this session, oldest first, including those of step-ups.
        public private(set) var proofs: [Proof]

        public init(proofs: [Proof]) {
            self.proofs = proofs
        }

        /// How long a step-up lasts: five minutes.
        public static let stepUpWindow: Int64 = 300
    }
}

extension Authentication.Grant {

    /// Whether a second factor or a passkey was passed within `window` seconds before `now`.
    public func isFresh(at now: Time.Instant, window: Int64 = Self.stepUpWindow) -> Bool {
        let earliest = now.secondsSinceUnixEpoch - window
        return proofs.contains { proof in
            proof.factor.isSecond
                && proof.instant.secondsSinceUnixEpoch >= earliest
                && proof.instant.secondsSinceUnixEpoch <= now.secondsSinceUnixEpoch
        }
    }

    /// The grant after a step-up with `proof`.
    public mutating func record(_ proof: Authentication.Proof) {
        proofs.append(proof)
    }
}
