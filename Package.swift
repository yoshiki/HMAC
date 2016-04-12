import PackageDescription

let package = Package(
    name: "HMAC",
    dependencies: [
                      .Package(url: "https://github.com/yoshiki/CryptoEssentials.git", majorVersion: 0, minor: 3)
    ]
)
