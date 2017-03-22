import java.io.*;
import java.nio.file.*;
import java.net.*;
import javax.crypto.*;
import java.nio.charset.*;
import java.util.Base64;
import javax.crypto.*;
import java.security.*;

class TCPServer {
  public static void main(String argv[]) throws Exception {
    Crypto encrypter = new Crypto();
    ServerSocket welcomeSocket = new ServerSocket(6789);
    SecretKey DH_DESSecret = null;
    String dhParams = "";
 
    Socket connectionSocket = welcomeSocket.accept();

    while(true) { // wait for a connection
      //Socket connectionSocket = welcomeSocket.accept();
      BufferedReader inFromClient =
        new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
      DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
      
      KeyPair kp = null;
      String basePath = new File("").getAbsolutePath();

      // Check if the key files exist already
      File t1 = new File(basePath + "/keys/server/dh_public");
      File t2 = new File(basePath + "/keys/server/dh_private");
      if (t1.exists() && t2.exists()) {
        System.out.println("=== KEY FILES ALREADY EXIST, OVERWRITTING ===");
        t1.delete();
        t2.delete();
      } else {
        System.out.println("=== KEY FILES WILL BE CREATED ===");
      }

      // === PERFORM DIFFIE HELLMAN ONCE WE GET PARAMS FROM CLIENT ===
      // params should be the first thing that we get from the client
      dhParams = inFromClient.readLine().trim();
      System.out.println("RECEIVED DH PARAMS: " + dhParams);

      // === DIFFIE HELLMAN: 3 ===
      // generate this client's keypair
      kp = encrypter.DH_genKeyPair(dhParams);
      // Write the key pair files
      basePath = new File("").getAbsolutePath();
      System.out.println(basePath);

      encrypter.DH_keyPairToFiles(kp, basePath + "/keys/server/");
      // === DIFFIE HELLMAN: 4 ===
      byte[] otherPubkBytes = null;
      try {
        // will relative path work?
        Path path = Paths.get(basePath + "/keys/client/dh_public");
        otherPubkBytes = Files.readAllBytes(path.toAbsolutePath());

        // === DIFFIE HELLMAN: 5 ===
        DH_DESSecret = encrypter.DH_genDESSecret(kp.getPrivate(), otherPubkBytes);
      } catch (FileNotFoundException e) {}

      System.out.println("DES KEY LEN: " + new String(DH_DESSecret.getEncoded()).length() + "\nKEY: "
                         + new String(DH_DESSecret.getEncoded()));

      
      // === MESSAGING PHASE ===

      // get the cipher text from the client and decrypt it
      System.out.println("=== RECEIVING ENCRYPTED MESSAGE ===\nDecrypting"); 
      String cipherText = inFromClient.readLine();
      byte[] b64_decodedCipherText = Base64.getDecoder().decode(cipherText.getBytes());
      byte[] clearText = encrypter.DES_decrypt(b64_decodedCipherText, DH_DESSecret);
      System.out.println("CIPHER TEXT BYTES B64 LEN: " + b64_decodedCipherText.length);
      System.out.println("B64 CIPHER TEXT: " + cipherText);
      System.out.println("=== DECRYPTED MESSAGE ===\n" + new String(clearText));

    }
  }
}
