import java.security.*;
import javax.crypto.*;
import javax.crypto.Cipher;

class Crypto {
  /*
   * Provides:
   *  - Helpers for performing Diffie-Helman key exchanges
   *  - Helpers for performing RSA based key excanges?
   *  - DES encryption
   *  - DES decryption
   *  - RSA Encryption
   *  - RSA Decryption
   *  - HMAC message validation
   */

  // User may pass from enum to setup for type of encryption/decryption desired
  public enum CIPHER_ALGORITHM {
    DES,
    RSA 
  };

  private String cipherAlgorithm;
  private Cipher cipher;
  private KeyGenerator keyGen;

  /**
   * @author Cory Sabol - cssabol@uncg.edu
   * 
   * Configure the Crypto instance to perform the specified type of Encryption 
   * CIPHER_ALGORITHM cipherAlgorithm - the algorithm to be used
   */
  public void setCrypto(CIPHER_ALGORITHM cipherAlgorithm) throws NoSuchAlgorithmException {
    // Do setup based on the algorithm specified
    switch (cipherAlgorithm) {
      case DES:
        this.cipherAlgorithm = "DES";
        break;
      case RSA:
        this.cipherAlgorithm = "RSA";
        break;
      default:
        this.cipherAlgorithm = "DES";
    }

    try {
      keyGen = KeyGenerator.getInstance(this.cipherAlgorithm);
      cipher = Cipher.getInstance(this.cipherAlgorithm);
    } catch (NoSuchPaddingException e) {
      System.err.println("invalid padding");
    }
  }

  /**
   * Return the Cipher object instance
   */
  public Cipher getCipher() {
    return cipher;
  }

  /**
   * Return the KeyGenerator object instance
   */
  public KeyGenerator getKeyGen() {
    return keyGen;
  }
}

