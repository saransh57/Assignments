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
    message: Potentially sensitive data was observed to be stored in UserDefaults, which is not adequate protection of sensitive information. For data of a sensitive nature, applications should leverage the Keychain.
    severity: WARNING
    metadata:
      likelihood: LOW
      impact: HIGH
      confidence: MEDIUM
      category: security
      cwe:
        - "CWE-311: Missing Encryption of Sensitive Data"
      masvs:
        - "MASVS-STORAGE-1: The app securely stores sensitive data"
      owasp:
        - A03:2017 - Sensitive Data Exposure
        - A04:2021 - Insecure Design
      references:
        - https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/ValidatingInput.html
        - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
      subcategory:
        - vuln
      technology:
        - ios
        - macos
      license: Commons Clause License Condition v1.0[LGPL-2.1-only]
      vulnerability_class:
        - Cryptographic Issues
    languages:
      - swift
    options:
      symbolic_propagation: true
    patterns:
      - pattern-either:
          - pattern: |
              UserDefaults.standard.set($VALUE, forKey: "$KEY")
          - pattern: |
              UserDefaults.standard.set($VALUE, forKey: $KEY)
      - metavariable-regex:
          metavariable: $KEY
          regex: (?i).*(passcode|password|pass_word|passphrase|pass_code|pass_word|pass_phrase|api_key|apikey|secretkey|secret_key|secrettoken|secret_token|clientsecret|client_secret|cryptkey|cryptokey|crypto_key|cryptionkey|symmetrickey|privatekey|symmetric_key|private_key)$
      - focus-metavariable: $KEY
