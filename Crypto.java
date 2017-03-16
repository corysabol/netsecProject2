import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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
  private String keyGenAlgorithm;
  private Cipher cipher;
  private KeyGenerator keyGen;
  private SecretKey secretKey;

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
        this.cipherAlgorithm = "DES/CBC/NoPadding";
        keyGenAlgorithm = "DES";
        break;
      case RSA:
        this.cipherAlgorithm = "RSA";
        keyGenAlgorithm = "RSA";
        break;
      default:
        this.cipherAlgorithm = "DES/CBC/NoPadding";
        keyGenAlgorithm = "DES";
    }

    try {
      keyGen = KeyGenerator.getInstance(keyGenAlgorithm);
      cipher = Cipher.getInstance(this.cipherAlgorithm);
    } catch (NoSuchPaddingException e) {
      System.err.println("invalid padding");
    }
  }

  /**
   */
  public SecretKey generateSecretKey() {
    switch (keyGenAlgorithm) {
      case "DES":
        keyGen.init(56);
        break;
      case "RSA":
        break;        
    }
    return keyGen.generateKey();
  }

  /**
   */
  public void setSecretKey(String key) {

  }

  /**
   */
  public void setSecretKey(byte[] key) {

  }

  /**
   */
  public void setSecretKey(SecretKey key) {
    secretKey = key;
  }

  /**
   * @param byte[] data - The byte array containing the data to be transformed
   *
   * Encrypts the given data using the cipher that this Crypto instance was
   * initialized with.
   */
  public byte[] encrypt(byte[] data) {
    byte[] cipherText = null;

    // generate a key only if one hasn't already been set
    if (secretKey == null) {
      secretKey = keyGen.generateKey();
    }
    // InvalidKeyException
    try {
      cipher.init(cipher.ENCRYPT_MODE, secretKey);
    } catch (InvalidKeyException e) {
      System.err.println("Error: InvalidKey");
    }
    
    // IllegalBlockSizeException
    try {
      cipherText = cipher.doFinal(data);
    } catch (IllegalBlockSizeException e) {
      System.err.println("Error: IllegalBlockSize");
    } catch (BadPaddingException e) {
      System.err.println("Error: BadPadding");
    }

    return cipherText;
  }

  /**
   * @param byte[] data - The byte array containing the data to be transformed
   * @param IvParameterSpec IV - the initialization vector to be used during
   *                             data transformation
   *
   * Encrypts the given data using the cipher that this Crypto instance was
   * initialized with.
   */
  public byte[] encrypt(byte[] data, IvParameterSpec IV) {
    byte[] cipherText = null;

    // generate a key only if one hasn't already been set
    if (secretKey == null) {
      secretKey = keyGen.generateKey();
    }
    // InvalidKeyException
    try {
      cipher.init(cipher.ENCRYPT_MODE, secretKey, IV);
    } catch (InvalidKeyException e) {
      System.err.println("Error: InvalidKey");
    } catch (InvalidAlgorithmParameterException e) {
      System.err.println("Error: InvalidAlgorithmParameter");
    }
    
    // IllegalBlockSizeException
    try {
      cipherText = cipher.doFinal(data);
    } catch (IllegalBlockSizeException e) {
      System.err.println("Error: IllegalBlockSize");
    } catch (BadPaddingException e) {
      System.err.println("Error: BadPadding");
    }

    return cipherText;
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

