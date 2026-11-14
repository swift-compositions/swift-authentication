internal import ASCII
internal import Byte
internal import RFC_4648

extension Authentication {

    /// 32 random bytes handed to a client once: a pending sign-in, a browser binding, a challenge. The server keeps
    /// only its `digest`.
    public struct Token: Sendable, Hashable {

        /// 32 bytes.
        public let bytes: [UInt8]

        /// A fresh token from `generator`, which must be a cryptographically secure source.
        public init(using generator: inout some RandomNumberGenerator) {
            var bytes: [UInt8] = []
            bytes.reserveCapacity(32)
            for _ in 0..<4 {
                let word = generator.next()
                for shift in stride(from: 0, to: 64, by: 8) {
                    bytes.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
                }
            }
            self.bytes = bytes
        }

        /// The token a client sent back, as its base64url text without padding; `nil` unless it is 32 bytes.
        public init?(encoded: String) {
            guard !encoded.contains("="),
                let decoded = RFC_4648.Base64.URL.decode(encoded, strictness: .strict),
                decoded.count == 32
            else { return nil }
            self.bytes = decoded.map(\.underlying)
        }

        /// Base64url without padding: 43 characters, safe in a cookie, a URL or a form.
        public var encoded: String {
            let codes = RFC_4648.Base64.URL.encode(bytes.map(Byte.init(_:)), padding: false)
            return String(decoding: codes.map(\.underlying), as: UTF8.self)
        }

        /// What the server stores.
        public var digest: Digest { Digest(of: bytes) }
    }
}
