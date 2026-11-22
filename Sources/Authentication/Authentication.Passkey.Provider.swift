internal import RFC_4648

extension Authentication.Passkey {
    public struct Provider: Sendable, Hashable {
        public let name: String

        public init?(aaguid: [UInt8]) {
            guard aaguid.count == 16, let name = Self.names[aaguid] else { return nil }
            self.name = name
        }
    }
}

extension Authentication.Passkey.Provider {
    static let names: [[UInt8]: String] = Dictionary(
        uniqueKeysWithValues: [
            ("bada5566a7aa401fbd9645619a55120d", "1Password"),
            ("fbfc3007154e4ecc8c0b6e020557d7bd", "Apple Passwords"),
            ("dd4ec289e01d41c9bb8970fa845d4bf2", "iCloud Keychain"),
            ("d548826e79b4db40a3d811116f7e8349", "Bitwarden"),
            ("adce000235bcc60a648b0b25f1f05503", "Chrome on Mac"),
            ("b53976664885aa6bcebfe52262a439a2", "Chromium"),
            ("531126d6e717415c93203d9aa6981239", "Dashlane"),
            ("771b48fdd3d44f749232fc157ab0507a", "Edge on Mac"),
            ("f38095407f1449c1a8b38f813b225541", "Enpass"),
            ("ea9b8d664d011d213ce4b6b48cb575d4", "Google Password Manager"),
            ("a10c6dd9465e42268198c7c44b91c555", "Kaspersky Password Manager"),
            ("fdb141b25d84443e8a354698c205a502", "KeePassXC"),
            ("0ea242b443c44a1b8b17dd6d0b6baec6", "Keeper"),
            ("b78a0a556ef8d246a042ba0f6d55050c", "LastPass"),
            ("d345266801fd4c12926c83a4204853aa", "Microsoft Password Manager"),
            ("b84e404815dc4dd08640f4f60813c8af", "NordPass"),
            ("fa37f553f9b64adbac538bbb57ebdf0d", "Norton Password Manager"),
            ("50726f746f6e5061737350726f746f6e", "Proton Pass"),
            ("53414d53554e47000000000000000000", "Samsung Pass"),
            ("08987058cadc4b81b6e130de50dcbe96", "Windows Hello"),
            ("9ddd1817af5a4672a2b93e3dd95000a9", "Windows Hello"),
            ("6028b017b1d44c02b4b3afcdafc96bb2", "Windows Hello"),
        ].compactMap { hex, name in
            IETF.RFC.`4648`.Base16.decode(hex, skipPrefix: false).map { ($0.map(\.underlying), name) }
        }
    )
}
