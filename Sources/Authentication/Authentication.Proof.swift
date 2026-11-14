extension Authentication {

    /// A factor passed at an instant.
    public struct Proof: Sendable, Hashable {

        public let factor: Factor

        public let instant: Time.Instant

        public init(_ factor: Factor, at instant: Time.Instant) {
            self.factor = factor
            self.instant = instant
        }
    }
}
