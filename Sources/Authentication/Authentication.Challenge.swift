extension Authentication {

    /// A passkey challenge as the server stores it: the digest of the random bytes sent to the browser, and when
    /// it stops being accepted. The store removes it when it is used, so it is used once.
    public struct Challenge: Sendable, Hashable {

        public let digest: Digest

        public let expiry: Time.Instant

        /// Five minutes.
        public static let lifetime: Int64 = 300

        /// A challenge read back from storage.
        public init(digest: Digest, expiry: Time.Instant) {
            self.digest = digest
            self.expiry = expiry
        }

        /// A new challenge at `now`, and the token whose bytes go to the browser.
        public static func issue(
            at now: Time.Instant,
            using generator: inout some RandomNumberGenerator
        ) -> (token: Token, challenge: Challenge) {
            let token = Token(using: &generator)
            let expiry = Time.Instant(secondsSinceUnixEpoch: now.secondsSinceUnixEpoch + lifetime)
            return (token, Challenge(digest: token.digest, expiry: expiry))
        }
    }
}

extension Authentication.Challenge {

    /// Whether `bytes`, the challenge a browser's client data names, is this challenge and still live at `now`.
    public func check(_ bytes: [UInt8], at now: Time.Instant) throws(Authentication.Error) {
        guard digest.matches(bytes) else { throw .token }
        guard now < expiry else { throw .expired }
    }
}
