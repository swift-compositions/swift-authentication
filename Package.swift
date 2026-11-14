// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "swift-authentication",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: "Authentication", targets: ["Authentication"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-6238.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-4648.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-3986.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-standards/swift-fips-180-4.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-time.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-byte.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-ascii.git",
            branch: "main"
        ),
    ],
    targets: [
        .target(
            name: "Authentication",
            dependencies: [
                .product(name: "RFC 6238", package: "swift-rfc-6238"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
                .product(name: "RFC 3986", package: "swift-rfc-3986"),
                .product(name: "FIPS 180-4", package: "swift-fips-180-4"),
                .product(name: "Time", package: "swift-time"),
                .product(name: "Byte", package: "swift-byte"),
                .product(name: "ASCII", package: "swift-ascii"),
            ]
        ),
        .testTarget(
            name: "Authentication Tests",
            dependencies: [
                .target(name: "Authentication")
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    target.swiftSettings =
        (target.swiftSettings ?? []) + [
            .strictMemorySafety(),
            .enableUpcomingFeature("ExistentialAny"),
            .enableUpcomingFeature("InternalImportsByDefault"),
            .enableUpcomingFeature("MemberImportVisibility"),
            .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
            .enableUpcomingFeature("InferIsolatedConformances"),
            .enableExperimentalFeature("Lifetimes"),
            .treatAllWarnings(as: .error),
        ]
}
