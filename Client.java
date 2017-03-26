import java.io.*;
import java.nio.file.*;
import java.net.*;
import javax.crypto.*;
import java.nio.charset.*;
import java.util.Base64;
import javax.crypto.*;
import java.security.*;
 
class Client {

  public static void main(String argv[]) throws Exception {

    PublicKey RSA_serverPubKey = null;

    SecretKey DESSecret = null; // the secret created via DH

    String clearText = "Network Security\n";
    byte[] clearBytes = clearText.getBytes("UTF-8");
    byte[] cipherBytes;
    String cipherText;

    Socket serverConnSock = new Socket("localhost", 6789);
    DataOutputStream toServer = new DataOutputStream(serverConnSock.getOutputStream());
    BufferedReader inFromServer = new BufferedReader(new InputStreamReader(serverConnSock.getInputStream()));

    String basePath = new File("").getAbsolutePath();
    KeyPair kp = null;
    String dhParams = "";

    // RSA variables
    KeyPair RSA_kp = RSA_kp = CryptoUtil.RSA_genKeyPair();
    // create the RSA keypair files
    CryptoUtil.RSA_keysToFiles(RSA_kp, basePath + "/keys/client/");

    // === DIFFIE HELLMAN EXCHANGE ===
    DESSecret = doDiffieHellman(toServer, basePath);

    // === MESSAGING PHASE ===
    // Encrypt the clear text
    cipherBytes = CryptoUtil.DES_encrypt(clearBytes, DESSecret);
    System.out.println("CIPHER TEXT LEN: " + cipherBytes.length);
    System.out.println("=== MESSAGE ENCRYPTED ===\n" 
                       + "=== SENDING CIPHER TEXT===\n");
    // Base 64 encode the cipher text
    byte[] b64_cipherText = Base64.getEncoder().encode(cipherBytes);
    toServer.writeBytes(new String(b64_cipherText)); 
    toServer.flush();

    // === RSA BASED SECRET EXCHANGE ===
    RSA_kp = doRSAExchange(DESSecret);
    
    serverConnSock.close(); 

    // Delete the key files
    CryptoUtil.cleanUpKeyFiles(basePath + "/keys/client/"); 
  }

  public static SecretKey doDiffieHellman(DataOutputStream toServer, String basePath) 
    throws Exception {

    KeyPair kp = null;
    String dhParams = ""; 
    SecretKey DESSecret = null;

    // === DIFFIE HELLMAN: 1 ===
    dhParams = CryptoUtil.generateDHParams();

    System.out.println("=== GENERATED DH PARAMETERS: ===\n"
                       + dhParams + "\n=========================");
    // === DIFFIE HELLMAN: 2 ===
    toServer.writeBytes(new String(dhParams.getBytes())); 
    toServer.writeBytes("\n");
    toServer.flush();
    // === DIFFIE HELLMAN: 3 ===
    // generate this client's keypair
    kp = CryptoUtil.DH_genKeyPair(dhParams);
    // Write the key pair files
    basePath = new File("").getAbsolutePath();
    System.out.println(basePath);

    CryptoUtil.DH_keyPairToFiles(kp, basePath + "/keys/client/");
    
    // === DIFFIE HELLMAN: 4 ===
    // Assuming the server generated it's keypair the public key of the server
    // will be located at keys/server/dh_public for the sake of simplicity.
    byte[] otherPubkBytes = null;

    // Need to wait for server keys to be created
    try {
      Path path = Paths.get(basePath + "/keys/server/dh_public");
      System.out.println("Waiting for server DH public key to become available");
      while (!path.toFile().exists()) {} // wait for file to be available
      System.out.println("File ready... Reading.");
      otherPubkBytes = Files.readAllBytes(path.toAbsolutePath());

      System.out.println("SERVER PUBKEY b64: " 
          + Base64.getEncoder().encode(otherPubkBytes));

      // === DIFFIE HELLMAN: 5 ===
      DESSecret = CryptoUtil.DH_genDESSecret(kp.getPrivate(), otherPubkBytes);
    } catch (FileNotFoundException e) {}

    System.out.println("DES KEY LEN: " + new String(DESSecret.getEncoded()).length() + "\nKEY: "
                       + new String(DESSecret.getEncoded()));

    return DESSecret;
  }

  public static KeyPair doRSAExchange(SecretKey DESSecret) {
  
    // === RSA BASED SECRET EXCHANGE ===
    // 1. Simply transfer the existing DES secret the was established with DH 
    // 2. encrypt the DES secret using the recipients public key
    // 3. Transmit the encrypted secret to the recipient
    // 4. await response encrypted with this client's public key
    // 5. decrypt response stating that message was received

    return null;
  }

  // specifically check if the client dh keys exist
  // this is horrible not portable code
  public static boolean DH_keysExist(String dir) throws Exception {
    Path pub = Paths.get(dir + "/dh_public");
    Path priv = Paths.get(dir + "/dh_private");

    if (pub.toFile().exists() && priv.toFile().exists()) {
      return true;
    }
    return false;
  }

  // specifically check if the client RSA keys exist
  // this is horrible not portable code
  public static boolean RSA_keysExist(String dir) {
    Path pub = Paths.get(dir + "/RSA_public.key");
    Path priv = Paths.get(dir + "/RSA_private.key");

    if (pub.toFile().exists() && priv.toFile().exists()) {
      return true;
    }
    return false;
  }

  public static String benchMarkCrypto(SecretKey DH_DESSecret) throws Exception {
    // === BENCH MARKS 10000 word list ===
    PublicKey RSA_serverPubKey = null;

    File wordList = new File("10000words.txt");
    BufferedReader wordReader = new BufferedReader(new FileReader(wordList));
    String word = null;
    long startTime;
    long estTime;
    byte[] encWordBytes = null;

    long DES_elapsedTime = 0;
    // DES ENCRYPTION
    while ((word = wordReader.readLine()) != null) {
      startTime = System.nanoTime();
      encWordBytes = CryptoUtil.DES_encrypt(word.getBytes(), DH_DESSecret);
      estTime = System.nanoTime() - startTime;
      // send the encrypted word to the server to time decryption
      // sum times
      DES_elapsedTime += estTime;
    }
    System.out.println("DES ELAPSED ENCRYPTION TIME: " + DES_elapsedTime);

    long RSA_elapsedTime = 0;
    // RSA ENCRYPTION
    // need the server public key
    while ((word = wordReader.readLine()) != null) {
      startTime = System.nanoTime();
      encWordBytes = CryptoUtil.RSA_encrypt(word.getBytes(), RSA_serverPubKey);
      estTime = System.nanoTime() - startTime;
      // send the encrypted word to the server to time decryption
      // sum times
      RSA_elapsedTime += estTime;
    }

    System.out.println("DES ELAPSED ENCRYPTION TIME: " + DES_elapsedTime);
    
    return null;
  }

}
