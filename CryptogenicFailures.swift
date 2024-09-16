import Foundation
import CommonCrypto

// MARK: - Vulnerable & Safe Cryptographic Usage

class CryptographyManager {

    // MARK: - Vulnerable Examples

    // 1. Vulnerable: Hardcoded Secret Key
    func vulnerableHardcodedKeyEncryption(data: Data) -> Data? {
        let key = "hardcodedsecretkey"
        let iv = "1234567890123456" // Insecure fixed IV
        return performAESEncryption(data: data, key: key, iv: iv)
    }

    // 2. Vulnerable: Weak Hash Function (MD5)
    func vulnerableWeakHash(data: Data) -> String {
        return md5Hash(data: data) // MD5 is vulnerable to collision attacks
    }

    // 3. Vulnerable: Using ECB Mode for AES
    func vulnerableECBEncryption(data: Data, key: String) -> Data? {
        return performAESEncryption(data: data, key: key, iv: nil, options: CCOptions(kCCOptionECBMode))
    }

    // 4. Vulnerable: Predictable Random Number Generation
    func vulnerablePredictableRandomKey() -> String {
        srand48(12345) // Predictable seed
        let randomKey = (0..<16).map { _ in String(format: "%02x", arc4random_uniform(255)) }.joined()
        return randomKey
    }

    // 5. Vulnerable: Storing Sensitive Data in Plain Text
    func vulnerableStorePlaintextPassword(password: String) {
        UserDefaults.standard.set(password, forKey: "userPassword") // Plaintext storage
    }

    // 6. Vulnerable: Insecure SHA-1 Usage
    func vulnerableSHA1Hash(data: Data) -> String {
        return sha1Hash(data: data) // SHA-1 is vulnerable to attacks
    }

    // 7. Vulnerable: Hardcoded Salt for Hashing
    func vulnerableHardcodedSaltHash(password: String) -> String {
        let salt = "staticSalt"
        return pbkdf2Hash(password: password, salt: salt)
    }

    // 8. Vulnerable: Using Deprecated DES Algorithm
    func vulnerableDESEncryption(data: Data, key: String) -> Data? {
        return performDESEncryption(data: data, key: key) // DES is outdated and insecure
    }

    // 9. Vulnerable: Insecure Key Derivation (Single Iteration)
    func vulnerableInsecureKeyDerivation(password: String) -> String {
        let salt = randomSalt()
        return pbkdf2Hash(password: password, salt: salt, iterations: 1) // Too few iterations
    }

    // 10. Vulnerable: Insecure Password Hashing Without Salt
    func vulnerableNoSaltHash(password: String) -> String {
        let data = password.data(using: .utf8)!
        return sha256Hash(data: data) // No salt added
    }

    // MARK: - Safe Examples

    // 1. Safe: Using Secure Key from Keychain/Environment
    func safeKeyEncryption(data: Data) -> Data? {
        let key = getSecureKeyFromKeychain() // Retrieve secure key from Keychain or environment
        let iv = randomIV()
        return performAESEncryption(data: data, key: key, iv: iv)
    }

    // 2. Safe: Using SHA-256 for Hashing
    func safeSHA256Hash(data: Data) -> String {
        return sha256Hash(data: data) // SHA-256 is currently secure
    }

    // 3. Safe: AES with CBC Mode and Random IV
    func safeCBCEncryption(data: Data, key: String) -> Data? {
        let iv = randomIV()
        return performAESEncryption(data: data, key: key, iv: iv, options: 0)
    }

    // 4. Safe: Cryptographically Secure Random Key Generation
    func safeRandomKey() -> String {
        var keyData = Data(count: 16)
        let result = keyData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        return result == errSecSuccess ? keyData.map { String(format: "%02x", $0) }.joined() : ""
    }

    // 5. Safe: Storing Hashed and Salted Password
    func safeStoreHashedPassword(password: String) {
        let salt = randomSalt()
        let hashedPassword = pbkdf2Hash(password: password, salt: salt)
        UserDefaults.standard.set(hashedPassword, forKey: "userPassword")
    }

    // 6. Safe: Using SHA-256 Instead of SHA-1
    func safeSHA256Hash(data: Data) -> String {
        return sha256Hash(data: data) // SHA-256 is secure
    }

    // 7. Safe: Using Random Salt for Hashing
    func safeRandomSaltHash(password: String) -> String {
        let salt = randomSalt()
        return pbkdf2Hash(password: password, salt: salt)
    }

    // 8. Safe: Using AES Instead of DES
    func safeAESEncryption(data: Data, key: String) -> Data? {
        let iv = randomIV()
        return performAESEncryption(data: data, key: key, iv: iv) // AES is secure
    }

    // 9. Safe: Key Derivation with Sufficient Iterations
    func safeKeyDerivation(password: String) -> String {
        let salt = randomSalt()
        return pbkdf2Hash(password: password, salt: salt, iterations: 10000) // Strong iterations count
    }

    // 10. Safe: Salted Password Hashing with PBKDF2
    func safeSaltedHash(password: String) -> String {
        let salt = randomSalt()
        return pbkdf2Hash(password: password, salt: salt)
    }

    // MARK: - Helper Functions

    private func performAESEncryption(data: Data, key: String, iv: String?, options: CCOptions = 0) -> Data? {
        // AES encryption logic here using CommonCrypto
        return nil
    }

    private func performDESEncryption(data: Data, key: String) -> Data? {
        // DES encryption logic here (not recommended)
        return nil
    }

    private func md5Hash(data: Data) -> String {
        // MD5 hash logic here
        return ""
    }

    private func sha1Hash(data: Data) -> String {
        // SHA-1 hash logic here
        return ""
    }

    private func sha256Hash(data: Data) -> String {
        // SHA-256 hash logic here using CommonCrypto
        return ""
    }

    private func pbkdf2Hash(password: String, salt: String, iterations: Int = 10000) -> String {
        // PBKDF2 logic here using CommonCrypto
        return ""
    }

    private func randomSalt() -> String {
        // Generate random salt logic here
        return "randomSalt"
    }

    private func randomIV() -> String {
        // Generate random IV logic here
        return "randomIV"
    }

    private func getSecureKeyFromKeychain() -> String {
        // Logic to get key from secure storage like Keychain or environment
        return "secureKey"
    }
}

// MARK: - Usage Examples

let cryptoManager = CryptographyManager()
let data = "SensitiveData".data(using: .utf8)!

// Vulnerable Usages (DO NOT USE IN PRODUCTION)
cryptoManager.vulnerableHardcodedKeyEncryption(data: data)
cryptoManager.vulnerableWeakHash(data: data)
cryptoManager.vulnerableECBEncryption(data: data, key: "insecureKey")
cryptoManager.vulnerablePredictableRandomKey()
cryptoManager.vulnerableStorePlaintextPassword(password: "password123")
cryptoManager.vulnerableSHA1Hash(data: data)
cryptoManager.vulnerableHardcodedSaltHash(password: "password123")
cryptoManager.vulnerableDESEncryption(data: data, key: "insecureKey")
cryptoManager.vulnerableInsecureKeyDerivation(password: "password123")
cryptoManager.vulnerableNoSaltHash(password: "password123")

// Safe Usages
cryptoManager.safeKeyEncryption(data: data)
cryptoManager.safeSHA256Hash(data: data)
cryptoManager.safeCBCEncryption(data: data, key: "secureKey")
cryptoManager.safeRandomKey()
cryptoManager.safeStoreHashedPassword(password: "password123")
cryptoManager.safeSHA256Hash(data: data)
cryptoManager.safeRandomSaltHash(password: "password123")
cryptoManager.safeAESEncryption(data: data, key: "secureKey")
cryptoManager.safeKeyDerivation(password: "password123")
cryptoManager.safeSaltedHash(password: "password123")
