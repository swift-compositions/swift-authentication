extension Authentication {

    /// A sign-in that passed its first factor and waits for a second: never a session itself.
    ///
    /// The client holds the pending token and a browser token (in a cookie); the server stores this value, which
    /// holds only their digests. It lasts five minutes and allows five attempts.
    public struct Pending: Sendable, Hashable {

        /// The digest of the pending token.
        public let digest: Digest

        /// The digest of the browser token it is tied to.
        public let binding: Digest

        /// The first factor.
        public let first: Proof

        /// When it stops being accepted.
        public let expiry: Time.Instant

        /// Attempts at a second factor still allowed.
        public private(set) var attemptsLeft: Int

        /// Five minutes.
        public static let lifetime: Int64 = 300

        /// Five attempts.
        public static let attempts = 5

        /// A pending sign-in read back from storage.
        public init(digest: Digest, binding: Digest, first: Proof, expiry: Time.Instant, attemptsLeft: Int) {
            self.digest = digest
            self.binding = binding
            self.first = first
            self.expiry = expiry
            self.attemptsLeft = attemptsLeft
        }

        /// A new pending sign-in after `first`, tied to the browser that holds `browser`, and the token to hand
        /// that browser.
        public static func begin(
            after first: Proof,
            browser: Token,
            using generator: inout some RandomNumberGenerator
        ) -> (token: Token, pending: Pending) {
            let token = Token(using: &generator)
            let expiry = Time.Instant(secondsSinceUnixEpoch: first.instant.secondsSinceUnixEpoch + lifetime)
            let pending = Pending(
                digest: token.digest,
                binding: browser.digest,
                first: first,
                expiry: expiry,
                attemptsLeft: attempts
            )
            return (token, pending)
        }
    }
}

extension Authentication.Pending {

    /// Whether `token`, presented by the browser holding `browser`, may attempt a second factor at `now`.
    public func check(
        token: Authentication.Token,
        browser: Authentication.Token,
        at now: Time.Instant
    ) throws(Authentication.Error) {
        guard digest.matches(token.bytes) else { throw .token }
        guard binding.matches(browser.bytes) else { throw .binding }
        guard now < expiry else { throw .expired }
        guard attemptsLeft > 0 else { throw .exhausted }
    }

    /// The pending sign-in after a second factor that did not verify.
    public mutating func fail() {
        attemptsLeft = max(attemptsLeft - 1, 0)
    }

    /// The grant of a session, once `second` has verified.
    public func complete(with second: Authentication.Proof) throws(Authentication.Error) -> Authentication.Grant {
        guard second.factor.isSecond else { throw .factor(second.factor) }
        return Authentication.Grant(proofs: [first, second])
    }
}
