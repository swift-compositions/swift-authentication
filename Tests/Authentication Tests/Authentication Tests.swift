import Testing

@testable import Authentication

@Suite
struct `Authentication Tests` {

    static func at(_ seconds: Int64) -> Time.Instant {
        Time.Instant(secondsSinceUnixEpoch: seconds)
    }

    @Test
    func `a digest is the SHA-256 of the secret`() {
        let digest = Authentication.Digest(of: Array("abc".utf8))
        #expect(digest.bytes.first == 0xba)
        #expect(digest.bytes.last == 0xad)
        #expect(digest.matches(Array("abc".utf8)))
        #expect(!digest.matches(Array("abd".utf8)))
        #expect(Authentication.Digest(bytes: digest.bytes) == digest)
        #expect(Authentication.Digest(bytes: [1, 2, 3]) == nil)
    }

    @Test
    func `a token is 32 bytes and round-trips as 43 base64url characters`() {
        var generator = SplitMix64(seed: 1)
        let token = Authentication.Token(using: &generator)
        #expect(token.bytes.count == 32)
        #expect(token.encoded.count == 43)
        #expect(Authentication.Token(encoded: token.encoded) == token)
        #expect(Authentication.Token(encoded: token.encoded + "=") == nil)
        #expect(Authentication.Token(encoded: String(token.encoded.dropLast(2))) == nil)
        let next = Authentication.Token(using: &generator)
        #expect(next != token)
    }

    @Test
    func `a pending sign-in completes with a second factor from the same browser in time`() throws {
        var generator = SplitMix64(seed: 2)
        let browser = Authentication.Token(using: &generator)
        let first = Authentication.Proof(.emailCode, at: Self.at(1000))
        let (token, pending) = Authentication.Pending.begin(after: first, browser: browser, using: &generator)
        #expect(pending.attemptsLeft == 5)
        #expect(pending.expiry == Self.at(1300))
        try pending.check(token: token, browser: browser, at: Self.at(1299))
        let grant = try pending.complete(with: Authentication.Proof(.authenticatorApp, at: Self.at(1010)))
        #expect(grant.proofs.map(\.factor) == [.emailCode, .authenticatorApp])
        #expect(Authentication.Requirement.secondFactor.isSatisfied(by: grant.proofs))
    }

    @Test
    func `a pending sign-in is refused when late, from another browser, with another token, or worn out`() {
        var generator = SplitMix64(seed: 3)
        let browser = Authentication.Token(using: &generator)
        let other = Authentication.Token(using: &generator)
        let first = Authentication.Proof(.provider, at: Self.at(0))
        let (token, begun) = Authentication.Pending.begin(after: first, browser: browser, using: &generator)
        var pending = begun
        #expect(throws: Authentication.Error.expired) { try pending.check(token: token, browser: browser, at: Self.at(300)) }
        #expect(throws: Authentication.Error.binding) { try pending.check(token: token, browser: other, at: Self.at(1)) }
        #expect(throws: Authentication.Error.token) { try pending.check(token: other, browser: browser, at: Self.at(1)) }
        for _ in 0..<5 { pending.fail() }
        #expect(pending.attemptsLeft == 0)
        #expect(throws: Authentication.Error.exhausted) { try pending.check(token: token, browser: browser, at: Self.at(1)) }
        pending.fail()
        #expect(pending.attemptsLeft == 0)
    }

    @Test
    func `a first factor does not complete a pending sign-in`() {
        var generator = SplitMix64(seed: 4)
        let browser = Authentication.Token(using: &generator)
        let (_, pending) = Authentication.Pending.begin(
            after: Authentication.Proof(.emailCode, at: Self.at(0)),
            browser: browser,
            using: &generator
        )
        #expect(throws: Authentication.Error.factor(.provider)) {
            try pending.complete(with: Authentication.Proof(.provider, at: Self.at(1)))
        }
    }

    @Test
    func `requirements`() {
        let email = Authentication.Proof(.emailCode, at: Self.at(0))
        let provider = Authentication.Proof(.provider, at: Self.at(0))
        let passkey = Authentication.Proof(.passkey, at: Self.at(0))
        let app = Authentication.Proof(.authenticatorApp, at: Self.at(0))
        let recovery = Authentication.Proof(.recoveryCode, at: Self.at(0))
        #expect(Authentication.Requirement.oneFactor.isSatisfied(by: [email]))
        #expect(!Authentication.Requirement.oneFactor.isSatisfied(by: []))
        #expect(!Authentication.Requirement.secondFactor.isSatisfied(by: [email]))
        #expect(!Authentication.Requirement.secondFactor.isSatisfied(by: [email, provider]))
        #expect(!Authentication.Requirement.secondFactor.isSatisfied(by: [app]))
        #expect(Authentication.Requirement.secondFactor.isSatisfied(by: [provider, recovery]))
        #expect(Authentication.Requirement.secondFactor.isSatisfied(by: [passkey]))
        #expect(Authentication.Requirement.passkey.isSatisfied(by: [passkey]))
        #expect(!Authentication.Requirement.passkey.isSatisfied(by: [email, app]))
        #expect(!Authentication.Requirement.passkey.isSatisfied(by: [provider, recovery]))
    }

    @Test
    func `a step-up is fresh for five minutes after a second factor`() {
        var grant = Authentication.Grant(proofs: [Authentication.Proof(.emailCode, at: Self.at(0))])
        #expect(!grant.isFresh(at: Self.at(10)))
        grant.record(Authentication.Proof(.passkey, at: Self.at(100)))
        #expect(grant.isFresh(at: Self.at(100)))
        #expect(grant.isFresh(at: Self.at(400)))
        #expect(!grant.isFresh(at: Self.at(401)))
        #expect(!grant.isFresh(at: Self.at(99)))
        #expect(grant.isFresh(at: Self.at(130), window: 30))
    }

    @Test
    func `a challenge is live for five minutes and matches only its own bytes`() throws {
        var generator = SplitMix64(seed: 5)
        let (token, challenge) = Authentication.Challenge.issue(at: Self.at(50), using: &generator)
        try challenge.check(token.bytes, at: Self.at(349))
        #expect(throws: Authentication.Error.expired) { try challenge.check(token.bytes, at: Self.at(350)) }
        #expect(throws: Authentication.Error.token) { try challenge.check([UInt8](repeating: 0, count: 32), at: Self.at(60)) }
    }

    @Test
    func `ten recovery codes, each usable once, typed loosely`() throws {
        var generator = SplitMix64(seed: 6)
        let (codes, stored) = Authentication.RecoveryCodes.generate(using: &generator)
        #expect(codes.count == 10)
        #expect(Set(codes).count == 10)
        #expect(stored.remaining == 10)
        for code in codes {
            #expect(code.count == 19)
            #expect(code.split(separator: "-").map(\.count) == [4, 4, 4, 4])
            #expect(code.allSatisfy { "abcdefghijklmnopqrstuvwxyz234567-".contains($0) })
        }
        let typed = " " + String(codes[3].uppercased().map { $0 == "-" ? " " : $0 }) + " "
        let left = try #require(stored.redeem(typed))
        #expect(left.remaining == 9)
        #expect(left.redeem(codes[3]) == nil)
        #expect(left.redeem(codes[4])?.remaining == 8)
        #expect(stored.redeem("aaaa-aaaa-aaaa-aaaa") == nil)
    }

    @Test
    func `a recovery code is read with 0 as o and 1 as l`() {
        #expect(Authentication.RecoveryCodes.normalized("AB0C-1D2E") == "abocld2e")
    }

    @Test
    func `the authenticator app accepts RFC 6238 codes once, one step either side`() throws {
        let app = try Authentication.AuthenticatorApp(secret: Array("12345678901234567890".utf8))
        // RFC 6238 Appendix B at time 59, SHA-1, last six digits of 94287082.
        #expect(app.verify("287082", at: Self.at(59), after: nil) == 1)
        #expect(app.verify("287 082", at: Self.at(59), after: nil) == 1)
        #expect(app.verify("287082", at: Self.at(59), after: 1) == nil)
        #expect(app.verify("287082", at: Self.at(89), after: 0) == 1)
        #expect(app.verify("287082", at: Self.at(120), after: nil) == nil)
        #expect(app.verify("000000", at: Self.at(59), after: nil) == nil)
    }

    @Test
    func `the authenticator app's address is the Key Uri Format`() throws {
        let app = try Authentication.AuthenticatorApp(secret: Array("12345678901234567890".utf8))
        #expect(app.base32Secret == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        #expect(
            app.uri(issuer: "Example Co", account: "ada@example.org")
                == "otpauth://totp/Example%20Co:ada%40example.org?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                + "&issuer=Example%20Co&algorithm=SHA1&digits=6&period=30"
        )
    }

    @Test
    func `enrolment makes a 20-byte secret`() {
        var generator = SplitMix64(seed: 7)
        let app = Authentication.AuthenticatorApp.enroll(using: &generator)
        #expect(app.secret.count == 20)
        #expect(app.base32Secret.count == 32)
    }

    @Test
    func `a passkey provider is named from the community list by its AAGUID`() {
        let iCloud: [UInt8] = [0xdd, 0x4e, 0xc2, 0x89, 0xe0, 0x1d, 0x41, 0xc9, 0xbb, 0x89, 0x70, 0xfa, 0x84, 0x5d, 0x4b, 0xf2]
        #expect(Authentication.Passkey.Provider(aaguid: iCloud)?.name == "iCloud Keychain")
        #expect(Authentication.Passkey.Provider(aaguid: Array("ProtonPassProton".utf8))?.name == "Proton Pass")
        #expect(Authentication.Passkey.Provider.names.count == 22)
        #expect(Authentication.Passkey.Provider(aaguid: [UInt8](repeating: 0, count: 16)) == nil)
        #expect(Authentication.Passkey.Provider(aaguid: Array(iCloud.prefix(15))) == nil)
    }

    @Test
    func `what a sign-in needs depends on its first factor, what the account holds and whether it chose passkeys only`() {
        let held: Set<Authentication.Factor> = [.passkey, .authenticatorApp, .recoveryCode]
        #expect(Authentication.Requirement.after(.emailCode, holding: held, passkeyOnly: false) == .secondFactor)
        #expect(Authentication.Requirement.after(.provider, holding: held, passkeyOnly: false) == .secondFactor)
        #expect(Authentication.Requirement.after(.provider, holding: held, passkeyOnly: false, trusting: [.passkey, .provider]) == .oneFactor)
        #expect(Authentication.Requirement.after(.provider, holding: held, passkeyOnly: true, trusting: [.passkey, .provider]) == .passkey)
        #expect(Authentication.Requirement.after(.emailCode, holding: [.authenticatorApp], passkeyOnly: true) == .secondFactor)
        #expect(Authentication.Requirement.after(.emailCode, holding: [], passkeyOnly: false) == .oneFactor)
    }

    @Test
    func `a step-up takes the passkey, else the app, a recovery code always, and passkeys only takes the passkey alone`() {
        #expect(Authentication.StepUp(holding: [.passkey, .authenticatorApp, .recoveryCode], passkeyOnly: false).ways == [.passkey, .recoveryCode])
        #expect(Authentication.StepUp(holding: [.authenticatorApp, .recoveryCode], passkeyOnly: false).ways == [.authenticatorApp, .recoveryCode])
        #expect(Authentication.StepUp(holding: [.recoveryCode], passkeyOnly: false).ways == [.recoveryCode])
        #expect(Authentication.StepUp(holding: [.passkey, .recoveryCode], passkeyOnly: true).ways == [.passkey])
        #expect(Authentication.StepUp(holding: [], passkeyOnly: false).ways.isEmpty)
    }

    @Test
    func `a step-up is met by one of its ways within the window, or by any fresh sign-in when it has none`() {
        let app = Authentication.StepUp(holding: [.passkey, .authenticatorApp], passkeyOnly: false)
        #expect(!app.isMet(by: Authentication.Grant(proofs: [Authentication.Proof(.authenticatorApp, at: Self.at(1000))]), at: Self.at(1100)))
        #expect(app.isMet(by: Authentication.Grant(proofs: [Authentication.Proof(.passkey, at: Self.at(1000))]), at: Self.at(1300)))
        #expect(!app.isMet(by: Authentication.Grant(proofs: [Authentication.Proof(.passkey, at: Self.at(1000))]), at: Self.at(1301)))
        let none = Authentication.StepUp(holding: [], passkeyOnly: false)
        #expect(none.isMet(by: Authentication.Grant(proofs: [Authentication.Proof(.emailCode, at: Self.at(1000))]), at: Self.at(1200)))
        #expect(!none.isMet(by: Authentication.Grant(proofs: [Authentication.Proof(.emailCode, at: Self.at(1000))]), at: Self.at(1400)))
    }
}
