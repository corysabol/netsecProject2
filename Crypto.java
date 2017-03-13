import java.security.*;
import javax.crypto.*;
import javax.crypto.Cipher;

/*
 * Crypto class shell
 * Eventually will house the crypto algorithms and helpers to perfom all the
 * crypto needs for the Client and Server applicaitons.
 */

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
   * Configure the Crypto instance to perform the specified type of Encryption 
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

  public void generatePrivKey_DES() {

  }
}

