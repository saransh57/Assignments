import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException

object InsecureCryptographyNoncompliant {
 
    @throws[NoSuchAlgorithmException]
    @throws[NoSuchProviderException]
    def weakKeySizeWithProviderString = {
        
        val keyGen = KeyPairGenerator.getInstance("RSA", "BC")
       // ruleid: insecure-cryptography
        keyGen.initialize(1024)
        keyGen.generateKeyPair
    }
 
}

rules:
  - id: insecure-cryptography
    languages:
      - scala
    severity: ERROR
    message: |
      This line is using an insecure key size. Use at least 2048 bits for RSA.
    patterns:
      - pattern: |
          $OBJ.initialize($KEY_SIZE)
    rules:
  - id: insecure-cryptography
    languages:
      - scala
    severity: ERROR
    message: |
      This line is using an insecure key size. Use at least 2048 bits for RSA.
    patterns:
      - pattern: $OBJ.initialize($KEY_SIZE)
    metavariable-regex:
      metavariable: $KEY_SIZE
      regex: ^(1\d{3}|[5-9]\d{2})$
    fix: |
      $OBJ.initialize(2048)
  
