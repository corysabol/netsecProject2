import java.net.*;
import java.io.*;

import java.security.*;
import java.security.spec.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.AlgorithmParameterGenerator;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.math.BigInteger;

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

  private final String DES_ALGORITHM = "DES/CBC/NoPadding";
  private final String DES_KEY_ALGORITHM = "DES";
  private final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
  private final String RSA_KEY_ALGORITHM = "RSA";

  /**
   * @author Cory Sabol - cssabol@uncg.edu
   * 
   * Configure the Crypto instance to perform the specified type of Encryption 
   * CIPHER_ALGORITHM cipherAlgorithm - the algorithm to be used
   */
  /*public void setCrypto(CIPHER_ALGORITHM cipherAlgorithm) throws NoSuchAlgorithmException {
    // Do setup based on the algorithm specified
    switch (cipherAlgorithm) {
      case DES:
        this.cipherAlgorithm = "DES/CBC/NoPadding";
        keyGenAlgorithm = "DES";
        break;
      case RSA:
        this.cipherAlgorithm = "RSA/ECB/PKCS1Padding";
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
  }*/

  /**
   * Generate a string containing Diffie Helman parameter;
   * g, p, and l
   * where g and p are primes and l is a secret value.
   * g and p will be sent to the other party involved in secret creation
   */
  public String generateDHParams() {
    String paramString = "";
    try {
      AlgorithmParameterGenerator dhParamGen = AlgorithmParameterGenerator.getInstance("DH");
      dhParamGen.init(1024);
      AlgorithmParameters params = dhParamGen.generateParameters(); 
      DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

      paramString = dhSpec.getP()+","+dhSpec.getG()+","+dhSpec.getL();
    } catch (NoSuchAlgorithmException e) {
      System.err.println("Error NoSuchAlgorithmException");
    } catch (InvalidParameterSpecException e) {
      System.err.println("Error InvalidParameterSpecException");
    }

    return paramString;
  }

  public KeyPair DH_genKeyPair(String DHParamStr) 
    throws InvalidKeyException, NoSuchAlgorithmException, 
           InvalidAlgorithmParameterException {

    String[] values = DHParamStr.split(",");
    BigInteger p = new BigInteger(values[0]);
    BigInteger g = new BigInteger(values[1]);
    int l = Integer.parseInt(values[2]);

    KeyPair keypair = null;

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
    keyGen.initialize(dhSpec);
    keypair = keyGen.generateKeyPair();

    /*// Get generated key pair
    PrivateKey privateKey = keypair.getPrivate();
    PublicKey publicKey = keypair.getPublic();
    */

    return keypair;

  }

  /**
   * write the keys to files
   */
  public void DH_keyPairToFiles(KeyPair kp, String dirPath) 
    throws FileNotFoundException, IOException {

    PrivateKey privk = kp.getPrivate();
    PublicKey pubk = kp.getPublic();
    byte[] privkBytes = privk.getEncoded();
    byte[] pubkBytes = pubk.getEncoded();
    File privkFile = new File(dirPath + "dh_private");
    File pubkFile = new File(dirPath + "dh_public");
    FileOutputStream privOut = null;
    FileOutputStream pubOut = null;
      
    privOut = new FileOutputStream(privkFile, false);
    pubOut = new FileOutputStream(pubkFile, false);
    // Write the keys to a file for retreival by the other party
    privOut.write(privkBytes);
    pubOut.write(pubkBytes);

    // close things up
    privOut.close();
    pubOut.close();

  }

  /**
   * Perform diffie helman key exchange protocol with second party
   * Assumes that the shared data has already been exchanged in some manner
   */
  public SecretKey DH_genDESSecret(PrivateKey privKey, byte[] otherPubKeyBytes) 
    throws InvalidKeySpecException, InvalidKeyException, NoSuchAlgorithmException {

    SecretKey secretKey = null;
    PublicKey otherPublicKey = null;

    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(otherPubKeyBytes);
    KeyFactory keyFact = KeyFactory.getInstance("DH");
    otherPublicKey = keyFact.generatePublic(x509KeySpec);

    // generate secret key with private key and other public key
    KeyAgreement ka = KeyAgreement.getInstance("DH");
    ka.init(privKey); // make sure we generate 56 bit des key
    ka.doPhase(otherPublicKey, true);

    secretKey = ka.generateSecret("DES");
    //secretKey = ka.generateSecret(this.DES_ALGORITHM); // Need to make sure this generates a 56 bit key

    return secretKey;
  }

  /**
   * @param byte[] data - The byte array containing the data to be transformed
   *
   * Encrypts the given data using the cipher that this Crypto instance was
   * initialized with.
   */
  public byte[] DES_encrypt(byte[] data, SecretKey secretKey) throws Exception {

    Cipher c = Cipher.getInstance(this.DES_ALGORITHM);
    byte[] cipherText = null;

    c.init(Cipher.ENCRYPT_MODE, secretKey);
    cipherText = c.doFinal(data);
    return cipherText;
  }

  /**
   *
   */
  public byte[] DES_decrypt(byte[] data, SecretKey secretKey) throws Exception {
    Cipher c = Cipher.getInstance(this.DES_ALGORITHM);
    byte[] clearText = null;

    c.init(Cipher.DECRYPT_MODE, secretKey);
    clearText = c.doFinal(data);
    return clearText;
  }

  /**
   * @param byte[] data - The byte array containing the data to be transformed
   * @param IvParameterSpec IV - the initialization vector to be used during
   *                             data transformation
   *
   * Encrypts the given data using the cipher that this Crypto instance was
   * initialized with.
   */
  public byte[] DES_encrypt(byte[] data, IvParameterSpec IV, SecretKey secretKey) throws Exception {
    Cipher c = Cipher.getInstance(this.DES_ALGORITHM);
    byte[] cipherText = null;

    c.init(Cipher.ENCRYPT_MODE, secretKey, IV);
    cipherText = c.doFinal(data);

    return cipherText;
  }

  /**
   * @param byte[] cipherText - the byte array containing the cipher text to
   *                            decrypt
   * @param IvParameterSpec IV - the initialization vector that was used to
   *                             encrypt the message
   * 
   * Decrypts the given data using the cipher and key that this Crypto instance
   * was initialized with.
   */
  public byte[] DES_decrypt(byte[] cipherText, IvParameterSpec IV, SecretKey secretKey) throws Exception {
    Cipher c = Cipher.getInstance(this.DES_ALGORITHM);
    byte[] clearText = null;

    c.init(Cipher.DECRYPT_MODE, secretKey, IV);
    clearText = c.doFinal(cipherText);

    return clearText;
  }
}

