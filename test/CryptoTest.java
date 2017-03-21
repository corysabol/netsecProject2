import static org.junit.Assert.assertEquals;
import org.junit.Test;
import java.security.*;
import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.*;
import java.util.Base64;

public class CryptoTest {
  @Test
  public void encryptsMessage_DES() throws NoSuchAlgorithmException, InvalidKeyException, 
         IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    // instance of crypto helper
    Crypto DES = new Crypto();
    // set up the DES cypher
    DES.setCrypto(Crypto.CIPHER_ALGORITHM.DES);
    
    // === TEST DATA ===
    String clearText = "Network Security";
    String correctMsg_b64 = "ZOF84xPpY65rfuZ3+Edicw==";

    // === TEST IV ===
    IvParameterSpec testIV = new IvParameterSpec("dGVzdGl2".getBytes());
    byte[] clearBytes = clearText.getBytes();
    byte[] cipherBytes;
    String cipherText;

    // === TEST KEY ===
    String testKey_b64 = "4PJ5ige6GrM=";
    byte[] testKey_raw = Base64.getDecoder().decode(testKey_b64.getBytes());
    String testKey_rawStr = new String(testKey_raw);

    // === Build a SecretKey instance ===
    SecretKey testKey_inst = new SecretKeySpec(testKey_raw, 0, testKey_raw.length, "DES");
    
    // === Set the key ===
    DES.setSecretKey(testKey_inst);

    // === PERFORM DES ENCRYPTION ON MESSAGE ===
    cipherBytes = DES.encrypt(clearBytes, testIV);
    byte[] cipherBytes_b64 = Base64.getEncoder().encode(cipherBytes);
    cipherText = new String(cipherBytes);

    assertEquals(correctMsg_b64, new String(cipherBytes_b64));
  }

  @Test
  public void decryptsMessage_DES() throws NoSuchAlgorithmException, InvalidKeyException, 
         IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    // instance of crypto helper
    Crypto DES = new Crypto();
    // set up the DES cypher
    DES.setCrypto(Crypto.CIPHER_ALGORITHM.DES);
    
    // === TEST DATA ===
    String correctMsg = "Network Security";
    String encryptedMsg_b64 = "ZOF84xPpY65rfuZ3+Edicw==";

    // === TEST IV ===
    IvParameterSpec testIV = new IvParameterSpec("dGVzdGl2".getBytes());
    byte[] encryptedMsg = Base64.getDecoder().decode(encryptedMsg_b64.getBytes());
    byte[] decryptedMsg;

    // === TEST KEY ===
    String testKey_b64 = "4PJ5ige6GrM=";
    byte[] testKey_raw = Base64.getDecoder().decode(testKey_b64.getBytes());
    String testKey_rawStr = new String(testKey_raw);

    // === Build a SecretKey instance ===
    SecretKey testKey_inst = new SecretKeySpec(testKey_raw, 0, testKey_raw.length, "DES");
    
    // === Set the key ===
    DES.setSecretKey(testKey_inst);

    // === PERFORM DES ENCRYPTION ON MESSAGE ===
    decryptedMsg = DES.decrypt(encryptedMsg, testIV);

    assertEquals(correctMsg, new String(decryptedMsg));   
  }
}
