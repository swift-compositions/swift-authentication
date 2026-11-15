extension Authentication {
    public struct StepUp: Sendable, Hashable {
        public let ways: [Factor]

        public init(holding held: Set<Factor>, passkeyOnly: Bool) {
            if passkeyOnly && held.contains(.passkey) {
                ways = [.passkey]
                return
            }
            var ways: [Factor] = []
            if held.contains(.passkey) {
                ways.append(.passkey)
            } else if held.contains(.authenticatorApp) {
                ways.append(.authenticatorApp)
            }
            if held.contains(.recoveryCode) { ways.append(.recoveryCode) }
            self.ways = ways
        }
    }
}

extension Authentication.StepUp {
    public func isMet(by grant: Authentication.Grant, at now: Time.Instant, window: Int64 = Authentication.Grant.stepUpWindow) -> Bool {
        let earliest = now.secondsSinceUnixEpoch - window
        return grant.proofs.contains { proof in
            proof.instant.secondsSinceUnixEpoch >= earliest
                && proof.instant.secondsSinceUnixEpoch <= now.secondsSinceUnixEpoch
                && (ways.isEmpty || ways.contains(proof.factor))
        }
    }
}
