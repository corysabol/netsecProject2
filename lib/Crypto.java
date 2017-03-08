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
   *
   *  The class behaves as follows:
   *    An instance of Crypto is created which can encapsulate the secrets for
   *    each type of encryption. The object is disposable, meaning that you
   *    could easily have various instances managing encrypted communications
   *    with various keys/secrets.
   *
   *    this of course may not entirely be necessary as we are simply going to
   *    leverage the java.security API
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
  public void setCrypto(CIPHER_ALGORITHM cipherAlgorithm,
      String privateKey) throws NoSuchAlgorithmException {
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

  public String getPrivatekey() {
    return null;
  }

  /* still need to determine the data types to use.
   * Likey byte arrays for everyting since it's easy to work with and can be
   * encoded as a string if desired.
  public <type> encrypt(<data>) {

  }

  public <type> decrypt(<data>) {

  }
  */

}

