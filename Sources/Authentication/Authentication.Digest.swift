internal import Byte
internal import FIPS_180_4

extension Authentication {

    /// The SHA-256 of a secret: what is stored in its place, so a stolen table gives no secret away.
    public struct Digest: Sendable, Hashable {

        /// 32 bytes.
        public let bytes: [UInt8]

        /// The digest of `secret`.
        public init(of secret: [UInt8]) {
            self.bytes = NIST.FIPS.`180`.`4`.SHA256.digest(secret.map(Byte.init(_:))).bytes.map(\.underlying)
        }

        /// A digest read back from storage: exactly 32 bytes.
        public init?(bytes: [UInt8]) {
            guard bytes.count == 32 else { return nil }
            self.bytes = bytes
        }

        /// Whether `secret` has this digest, compared in constant time.
        public func matches(_ secret: [UInt8]) -> Bool {
            let other = Digest(of: secret).bytes
            var difference: UInt8 = 0
            for index in bytes.indices {
                difference |= bytes[index] ^ other[index]
            }
            return difference == 0
        }
    }
}
