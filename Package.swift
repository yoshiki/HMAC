import PackageDescription

let package = Package(
    name: "HMAC",
    dependencies: [
                      .Package(url: "https://github.com/CryptoKitten/SHA1.git", majorVersion: 0, minor: 1)
                      ]
)
