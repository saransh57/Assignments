let passphrase = "mySecretPassphrase"
// ruleid: swift-user-defaults
UserDefaults.standard.set(passphrase, forKey: "passphrase")

let password = "myPassword123"
// ruleid: swift-user-defaults
UserDefaults.standard.set(password, forKey: "userPassword")

let apiKey = "12717-127163-a71367-127ahc"
// ruleid: swift-user-defaults
UserDefaults.standard.set(apiKey, forKey: "apiKey")

let cryptoKey = "AES128Key"
// ruleid: swift-user-defaults
UserDefaults.standard.set(cryptoKey, forKey: "cryptoKey")

/*
rules:
  - id: swift-user-defaults
    message: Sensitive data detected in UserDefaults; use Keychain for secure storage.
    severity: WARNING
    languages: [swift]
    patterns:
      - pattern-either:
          - pattern: |
              UserDefaults.standard.set($VALUE, forKey: "$KEY")
          - pattern: |
              UserDefaults.standard.set($VALUE, forKey: $KEY)
      - metavariable-regex:
          metavariable: $KEY
          regex: (?i).*(passcode|password|passphrase|apikey|secretkey|clientsecret|cryptokey|privatekey)$
    fix: |
      // Replace UserDefaults with Keychain storage
      let $VALUE_DATA = $VALUE.data(using: .utf8)!
      let status = SecItemAdd([
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: "$KEY",
          kSecValueData as String: $VALUE_DATA
      ] as CFDictionary, nil)

/*
