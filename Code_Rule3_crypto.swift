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
      regex: ^(10[0-1][0-9]|10[2-9]\d|[5-9]\d\d|1\d\d\d)$
    fix: |
      $OBJ.initialize(2048)
  
