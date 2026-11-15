extension Authentication {

    /// What an account needs before it gets a session.
    public enum Requirement: String, Sendable, Hashable, CaseIterable {

        /// Any one factor.
        case oneFactor = "one-factor"

        /// A passkey, or a first factor followed by a second factor. For an account that has a second factor.
        case secondFactor = "second-factor"

        /// A passkey and nothing else: an email code or a provider never suffices, whatever follows it.
        case passkey
    }
}

extension Authentication.Requirement {

    /// Whether `proofs` meet the requirement.
    public func isSatisfied(by proofs: [Authentication.Proof]) -> Bool {
        let factors = Set(proofs.map(\.factor))
        switch self {
        case .oneFactor:
            return !factors.isEmpty
        case .secondFactor:
            let hasFirst = factors.contains { !$0.isSecond }
            let hasSecond = factors.contains { $0.isSecond }
            return factors.contains(.passkey) || (hasFirst && hasSecond)
        case .passkey:
            return factors.contains(.passkey)
        }
    }
}

extension Authentication.Requirement {
    public static func after(
        _ first: Authentication.Factor,
        holding held: Set<Authentication.Factor>,
        passkeyOnly: Bool,
        trusting trusted: Set<Authentication.Factor> = [.passkey]
    ) -> Self {
        if passkeyOnly && held.contains(.passkey) { return .passkey }
        if trusted.contains(first) { return .oneFactor }
        return held.contains(where: \.isSecond) ? .secondFactor : .oneFactor
    }
}
