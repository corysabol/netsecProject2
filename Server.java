import java.io.*;
import java.nio.file.*;
import java.net.*;
import javax.crypto.*;
import java.nio.charset.*;
import java.util.Base64;
import javax.crypto.*;
import java.security.*;

class Server {
  public static void main(String argv[]) throws Exception {

    // Benchmark values
    long DES_startTime;
    long DES_endTime;
    long RSA_startTime;
    long RSA_endTime;
    long HMAC_startTime;
    long HMAC_endTime;

    ServerSocket welcomeSocket = new ServerSocket(6789);
    SecretKey DH_DESSecret = null;
    String dhParams = "";
 
    while(true) { // wait for a connection
      System.out.println("=== Awaiting a connection ===\n");

      Socket connectionSocket = welcomeSocket.accept();
      BufferedReader inFromClient =
        new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
      DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
      
      KeyPair kp = null;
      String basePath = new File("").getAbsolutePath();

      // === PERFORM DIFFIE HELLMAN ONCE WE GET PARAMS FROM CLIENT ===
      // params should be the first thing that we get from the client
      dhParams = inFromClient.readLine().trim();
      System.out.println("RECEIVED DH PARAMS: " + dhParams);

      // === DIFFIE HELLMAN: 3 ===
      // generate this client's keypair
      kp = CryptoUtil.DH_genKeyPair(dhParams);
      // Write the key pair files
      basePath = new File("").getAbsolutePath();
      System.out.println(basePath);

      CryptoUtil.DH_keyPairToFiles(kp, basePath + "/keys/server/");
      // === DIFFIE HELLMAN: 4 ===
      byte[] otherPubkBytes = null;
      try {
        Path path = Paths.get(basePath + "/keys/client/dh_public");
        System.out.println("Waiting for client DH public key to become available");
        while (!path.toFile().exists()) {} // wait for file to be available
        otherPubkBytes = Files.readAllBytes(path.toAbsolutePath());

        // === DIFFIE HELLMAN: 5 ===
        DH_DESSecret = CryptoUtil.DH_genDESSecret(kp.getPrivate(), otherPubkBytes);
      } catch (FileNotFoundException e) {}

      System.out.println("DES KEY LEN: " + new String(DH_DESSecret.getEncoded()).length() + "\nKEY: "
                         + new String(Base64.getEncoder().encode(DH_DESSecret.getEncoded())));

      
      // === MESSAGING PHASE ===
      // get the cipher text from the client and decrypt it using DES secret
      System.out.println("=== RECEIVING ENCRYPTED MESSAGE ===\nDecrypting"); 
      String cipherText = inFromClient.readLine();
      byte[] b64_decodedCipherText = Base64.getDecoder().decode(cipherText.getBytes());
      byte[] clearText = CryptoUtil.DES_decrypt(b64_decodedCipherText, DH_DESSecret);
      System.out.println("CIPHER TEXT BYTES B64 LEN: " + b64_decodedCipherText.length);
      System.out.println("B64 CIPHER TEXT: " + cipherText);
      System.out.println("=== DECRYPTED MESSAGE ===\n" + new String(clearText));

      // === RSA ===
      // create the server RSA keypair
      KeyPair RSA_kp = CryptoUtil.RSA_genKeyPair();
      // create the RSA keypair files
      CryptoUtil.RSA_keysToFiles(RSA_kp, basePath + "/keys/server/");

      // Get the encrypted DES key and decrypt it
      System.out.println("=== RECEIVING RSA ENCRYPTED DES SECRET ===");
      String RSA_DESKeyCipher = inFromClient.readLine();

      byte[] RSA_DESKeyBytes = 
        CryptoUtil.RSA_decrypt(Base64.getDecoder().decode(RSA_DESKeyCipher), RSA_kp.getPrivate());

      System.out.println("=== DES KEY DECRYPTED ===");
      DH_DESSecret = CryptoUtil.bytesToSecKey(RSA_DESKeyBytes);
      System.out.println("DES KEY: " + new String(Base64.getEncoder().encode(DH_DESSecret.getEncoded())));

      // === GET RSA ENCRYPTED MESSAGE W/ HMAC: [Network Security,HMAC] ===
      String RSACipherText = inFromClient.readLine(); 
      // parse the message apart for the HMAC and the actual message itself.
      // message is two base64 encoded messages separated by comma? 
      String b64_MsgHMAC = null;
      String encMsg = null;
      System.out.println("=== RSA MESSAGE + HMAC RECEIVED ===");
      //System.out.println("MSG PAIR: " + b64_decodedMsg);
      String[] splitMsg = new String(RSACipherText).split(",");
      b64_MsgHMAC = splitMsg[1];
      encMsg = splitMsg[0];
      // decrypt the message
      byte[] decMsg = CryptoUtil.RSA_decrypt(Base64.getDecoder().decode(encMsg.getBytes()), 
          RSA_kp.getPrivate());

      System.out.println("MSG: " + new String(decMsg) + " , b64 HMAC: " + b64_MsgHMAC);
      
      // === HMAC MESSAGE INTEGRITY CHECK ===
      System.out.println("=== VERIFYING MESSAGE INTEGRITY ===");
      // check the hash
      boolean validMessage = CryptoUtil.HMAC_compareHash(decMsg, 
          Base64.getDecoder().decode(b64_MsgHMAC), DH_DESSecret);

      if (!validMessage) {
        System.out.println("=== MESSAGE INTEGRITY COULD NOT BE VALIDATED, REJECTING ===\n");
      } else {
        System.out.println("=== MESSAGE INTEGRITY VERIFIED ===\n");
      }


      // === BENCHMARKS 10000 WORD LIST ===
      benchMarkCrypto(inFromClient, DH_DESSecret);

      // Clean up the key files
      //CryptoUtil.cleanUpKeyFiles(basePath + "/keys/server/");
    }
  }

    public static String benchMarkCrypto(BufferedReader inFromClient, 
      SecretKey DH_DESSecret) throws Exception {
    // === BENCH MARKS 10000 word list ===
    PrivateKey RSA_serverPrivKey = null;

    //File wordList = new File("10000words.txt");
    //BufferedReader wordReader = new BufferedReader(new FileReader(wordList));

    String word = null;
    long startTime = 0;
    long estTime = 0;
    byte[] encWordBytes = null;

    long DES_elapsedTime = 0;
    // DES ENCRYPTION
    while ((word = inFromClient.readLine()) != null) {
      startTime = System.nanoTime();
      encWordBytes = CryptoUtil.DES_decrypt(word.getBytes(), DH_DESSecret);
      estTime = System.nanoTime() - startTime;
      // send the encrypted word to the server to time decryption
      // sum times
      DES_elapsedTime += estTime;
    }
    System.out.println("DES ELAPSED DECRYPTION TIME: " + DES_elapsedTime);
    //wordReader.close();

    //wordReader = new BufferedReader(new FileReader(wordList));
    startTime = 0;
    estTime = 0;
    String basePath = new File("").getAbsolutePath();
    Path RSA_serverPrivKeyPath = Paths.get(basePath + "/keys/server/RSA_private.key");

    RSA_serverPrivKey = 
      CryptoUtil.bytesToPrivKey(
          Files.readAllBytes(RSA_serverPrivKeyPath.toAbsolutePath()),
          "RSA"     
      );

    long RSA_elapsedTime = 0;
    // RSA ENCRYPTION
    // need the server public key
    while ((word = inFromClient.readLine()) != null) {
      startTime = System.nanoTime();
      encWordBytes = CryptoUtil.RSA_decrypt(word.getBytes(), RSA_serverPrivKey);
      estTime = System.nanoTime() - startTime;
      // send the encrypted word to the server to time decryption
      // sum times
      RSA_elapsedTime += estTime;
    }

    System.out.println("RSA ELAPSED DECRYPTION TIME: " + RSA_elapsedTime);
    
    return null;
  }
}
