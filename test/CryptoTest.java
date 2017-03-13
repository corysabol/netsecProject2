import static org.junit.Assert.assertEquals;
import org.junit.Test;
import java.security.*;
import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.*;
import java.util.Base64;

public class CryptoTest {
  @Test
  public void encryptsMessage_DES() throws NoSuchAlgorithmException, InvalidKeyException, 
         IllegalBlockSizeException, BadPaddingException {
    // instance of crypto helper
    Crypto DES = new Crypto();
    // set up the DES cypher
    DES.setCrypto(Crypto.CIPHER_ALGORITHM.DES);
    String clearText = "Network Security";
    String correctMsg_b64 = "2CP9Rtr+ZR4pPh8Gup6URg==";
    byte[] clearBytes = clearText.getBytes();
    byte[] cipherBytes;
    String cipherText;

    // === TEST KEY ===
    String testKey_b64 = "Fe+/ve+/vVI777+977+977+9Cg==";
    byte[] testKey_raw = Base64.getDecoder().decode(testKey_b64.getBytes());
    String testKey_rawStr = new String(testKey_raw, StandardCharsets.UTF_8);
    // Build a SecretKey instance
    SecretKey testKey_inst = new SecretKeySpec(testKey_raw, 0, testKey_raw.length, "DES");

    // init the cipher to encrypt  
    DES.getCipher().init(DES.getCipher().ENCRYPT_MODE, testKey_inst);
    // === PERFORM DES ENCRYPTION ON MESSAGE ===
    cipherBytes = DES.getCipher().doFinal(clearBytes);
    cipherText = new String(cipherBytes, StandardCharsets.UTF_8); // Encode the message with UTF-8

    assertEquals(correctMsg_b64, new String(Base64.getEncoder().encode(cipherText.getBytes()),
                                            StandardCharsets.UTF_8));
  }
}
