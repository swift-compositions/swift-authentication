internal import ASCII
internal import Byte
internal import RFC_4648

extension Authentication {

    /// An account's recovery codes as the server stores them: the digests of those not yet used.
    ///
    /// A code is 80 random bits written as 16 Base32 letters and digits in groups of four, `abcd-efgh-ijkl-mnop`.
    /// Each works once. Making new ones replaces the old.
    public struct RecoveryCodes: Sendable, Hashable {

        /// The digests of the codes still unused.
        public let digests: [Digest]

        /// Recovery codes read back from storage.
        public init(digests: [Digest]) {
            self.digests = digests
        }

        /// Ten.
        public static let count = 10

        /// Ten new codes, to show the user once, and what to store.
        public static func generate(
            using generator: inout some RandomNumberGenerator
        ) -> (codes: [String], stored: RecoveryCodes) {
            var codes: [String] = []
            for _ in 0..<count {
                var bytes: [UInt8] = []
                for _ in 0..<10 {
                    bytes.append(UInt8.random(in: 0...255, using: &generator))
                }
                let letters = IETF.RFC.`4648`.Base32.encode(bytes.map(Byte.init(_:)), padding: false)
                let text = String(decoding: letters.map(\.underlying), as: UTF8.self).lowercased()
                let groups = stride(from: 0, to: 16, by: 4).map { start in
                    String(text.dropFirst(start).prefix(4))
                }
                codes.append(groups.joined(separator: "-"))
            }
            return (codes, RecoveryCodes(digests: codes.map { Digest(of: Array(normalized($0).utf8)) }))
        }

        /// A code as typed, made canonical: lower case, without spaces or hyphens, with 0 read as o and 1 as l,
        /// which Base32 does not use.
        public static func normalized(_ input: String) -> String {
            var result = ""
            for character in input.lowercased() {
                switch character {
                case " ", "-": continue
                case "0": result.append("o")
                case "1": result.append("l")
                default: result.append(character)
                }
            }
            return result
        }
    }
}

extension Authentication.RecoveryCodes {

    /// How many codes are left.
    public var remaining: Int { digests.count }

    /// The codes left after `input` is used, or `nil` when it is none of them. Every digest is compared, whether
    /// or not one matched.
    public func redeem(_ input: String) -> Authentication.RecoveryCodes? {
        let candidate = Array(Self.normalized(input).utf8)
        var matched: Int? = nil
        for (index, digest) in digests.enumerated() where digest.matches(candidate) && matched == nil {
            matched = index
        }
        guard let matched else { return nil }
        var left = digests
        left.remove(at: matched)
        return Authentication.RecoveryCodes(digests: left)
    }
}
