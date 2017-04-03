import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.AlgorithmParameterGenerator;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.math.BigInteger;

public final class CryptoUtil {
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

  public static final String DES_ALGORITHM = "DES/ECB/PKCS5Padding";
  public static final String DES_KEY_ALGORITHM = "DES";
  public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
  public static final String RSA_KEY_ALGORITHM = "RSA";
  public static final String HMAC_ALGORITHM = "HmacSHA1";

  /**
   * @author Cory Sabol - cssabol@uncg.edu
   * 
   */

  // make the constructor private so that it cannot be instantiated
  private CryptoUtil() {};

  // === DIFFIE HELLMAN ===
  /**
   * Generate a string containing Diffie Helman parameter;
   * g, p, and l
   * where g and p are primes and l is a secret value.
   * g and p will be sent to the other party involved in secret creation
   */
  public static String generateDHParams() {
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

  public static KeyPair DH_genKeyPair(String DHParamStr) 
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
  public static void DH_keyPairToFiles(KeyPair kp, String dirPath) 
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
  public static SecretKey DH_genDESSecret(PrivateKey privKey, byte[] otherPubKeyBytes) 
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

  // === DES ===
  /**
   * @param byte[] data - The byte array containing the data to be transformed
   *
   * Encrypts the given data using the cipher that this CryptoUtil instance was
   * initialized with.
   */
  public static byte[] DES_encrypt(byte[] data, SecretKey secretKey) throws Exception {

    Cipher c = Cipher.getInstance(CryptoUtil.DES_ALGORITHM);
    byte[] cipherText = null;

    c.init(Cipher.ENCRYPT_MODE, secretKey);
    cipherText = c.doFinal(data);
    return cipherText;
  }

  /**
   *
   */
  public static byte[] DES_decrypt(byte[] data, SecretKey secretKey) throws Exception {
    Cipher c = Cipher.getInstance(CryptoUtil.DES_ALGORITHM);
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
   * Encrypts the given data using the cipher that this CryptoUtil instance was
   * initialized with.
   */
  public static byte[] DES_encrypt(byte[] data, IvParameterSpec IV, SecretKey secretKey) throws Exception {
    Cipher c = Cipher.getInstance(CryptoUtil.DES_ALGORITHM);
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
   * Decrypts the given data using the cipher and key that this CryptoUtil instance
   * was initialized with.
   */
  public static byte[] DES_decrypt(byte[] cipherText, IvParameterSpec IV, SecretKey secretKey) throws Exception {
    Cipher c = Cipher.getInstance(CryptoUtil.DES_ALGORITHM);
    byte[] clearText = null;

    c.init(Cipher.DECRYPT_MODE, secretKey, IV);
    clearText = c.doFinal(cipherText);

    return clearText;
  }
  // ===========


  // === RSA ===
  public static KeyPair RSA_genKeyPair() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance(CryptoUtil.RSA_KEY_ALGORITHM);
    kpGen.initialize(2048);
    KeyPair kp = kpGen.generateKeyPair();
    return kp;
  }

  public static void RSA_keysToFiles(KeyPair kp, String outDir) 
    throws FileNotFoundException, IOException {
    // write the files to disk
    PrivateKey privk = kp.getPrivate();
    PublicKey pubk = kp.getPublic();
    byte[] privkBytes = privk.getEncoded();
    byte[] pubkBytes = pubk.getEncoded();
    
    File privkFile = new File(outDir + "RSA_private.key");
    File pubkFile = new File(outDir + "RSA_public.key");

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

  public static byte[] RSA_encrypt(byte[] data, PublicKey pubk) throws Exception {
    byte[] cipherBytes = null;
    Cipher c = Cipher.getInstance(CryptoUtil.RSA_ALGORITHM);
    c.init(Cipher.ENCRYPT_MODE, pubk);
    cipherBytes = c.doFinal(data);

    return cipherBytes;
  }

  public static byte[] RSA_decrypt(byte[] data, PrivateKey privk) throws Exception {
    byte[] clearBytes = null;
    Cipher c = Cipher.getInstance(CryptoUtil.RSA_ALGORITHM);
    c.init(Cipher.DECRYPT_MODE, privk);
    clearBytes = c.doFinal(data);

    return clearBytes;
  }
  
  // === HMAC ===
  public static byte[] HMAC_hash(byte[] data, SecretKey key) throws Exception {
    byte[] dataHash = null;

    Mac m = Mac.getInstance(CryptoUtil.HMAC_ALGORITHM);
    //SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_ALGORITHM);
    m.init(key);

    dataHash = m.doFinal(data);

    return dataHash;
  }

  /**
   * @param byte[] data
   * @param byte[] hash
   * @param SecretKey key
   * @return boolean
   *
   * Hashes data with shared secret and compares with received hash. If hashes
   * are the same returns true, false other wise
   */
  public static boolean HMAC_compareHash(byte[] data, byte[] hash, SecretKey key) throws Exception {
    byte[] dataHash = null;
    dataHash = CryptoUtil.HMAC_hash(data, key);
    String h1 = new String(dataHash);
    String h2 = new String(hash);

    if (h1.equals(h2)) {
      return true;
    }
  
    return false;
  }

  public static PublicKey bytesToPubKey(byte[] keyBytes, String algorithm) throws Exception {
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFact = KeyFactory.getInstance(algorithm);
    PublicKey pubKey = keyFact.generatePublic(x509KeySpec);
    
    return pubKey;
  }

  public static PrivateKey bytesToPrivKey(byte[] keyBytes, String algorithm) throws Exception {
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFact = KeyFactory.getInstance(algorithm);
    PrivateKey privKey = keyFact.generatePrivate(x509KeySpec);
    
    return privKey;
  }
  
  public static SecretKey bytesToSecKey(byte[] keyBytes) throws Exception {
    DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("DES");
    SecretKey secKey = keyFact.generateSecret(desKeySpec);
    
    return secKey;
  }

  // ============
  public static boolean cleanUpKeyFiles(String dir) {
    
    File f1 = new File(dir + "dh_public");
    File f2 = new File(dir + "dh_private");
    File f3 = new File(dir + "RSA_public.key");
    File f4 = new File(dir + "RSA_private.key");

    return (f1.delete() && f2.delete() && f3.delete() && f4.delete());
  }
}

