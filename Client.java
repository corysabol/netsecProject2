import java.io.*;
import java.nio.file.*;
import java.net.*;
import javax.crypto.*;
import java.nio.charset.*;
import java.util.Base64;
import javax.crypto.*;
import java.security.*;
 
class TCPClient {

  public static void main(String argv[]) throws Exception {

    // instance of crypto helper
    //Crypto CryptoUtil = new Crypto();
    SecretKey DH_DESSecret = null; // the secret created via DH
    SecretKey RSA_DESSecret = null; // The secret created via normal means and shared using RSA asymmetric encryption

    String clearText = "Network Security\n";
    byte[] clearBytes = clearText.getBytes("UTF-8");
    byte[] cipherBytes;
    String cipherText;

    /* === OVERVIEW ===
     *
     * This client program will establish a shared secret with a server program
     * using DiffieHelman, it will establish another shared secret with the
     * server using RSA ecryption.
     *
     * DiffieHellman:
     *  1. generate the dh paramters to share with the server
     *  2. Share the parameters with the server
     *  3. Generate keypair for client
     *  4. Read the resulting public key of the server
     *  5. use the publickey of the server and this clients private key to
     *     generate the shared DES secretkey
     *
     * ================*/


    Socket serverConnSock = new Socket("localhost", 6789);
    DataOutputStream toServer = new DataOutputStream(serverConnSock.getOutputStream());
    BufferedReader inFromServer = new BufferedReader(new InputStreamReader(serverConnSock.getInputStream()));

    boolean keysExist = false;
    String basePath = new File("").getAbsolutePath();
    KeyPair kp = null;
    String dhParams = "";


    // Check if the key files exist already
    File t1 = new File(basePath + "/keys/client/dh_public");
    File t2 = new File(basePath + "/keys/client/dh_private");
    if (t1.exists() && t2.exists()) {
      System.out.println("=== KEY FILES ALREADY EXIST, OVERWRITTING ===");
      t1.delete();
      t2.delete();
    } else {
      System.out.println("=== KEY FILES WILL BE CREATED ===");
    }

    if (!keysExist) {
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
    }
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
      DH_DESSecret = CryptoUtil.DH_genDESSecret(kp.getPrivate(), otherPubkBytes);
    } catch (FileNotFoundException e) {}

    System.out.println("DES KEY LEN: " + new String(DH_DESSecret.getEncoded()).length() + "\nKEY: "
                       + new String(DH_DESSecret.getEncoded()));

    // === MESSAGING PHASE ===
    // Encrypt the clear text
    cipherBytes = CryptoUtil.DES_encrypt(clearBytes, DH_DESSecret);
    System.out.println("CIPHER TEXT LEN: " + cipherBytes.length);
    System.out.println("=== MESSAGE ENCRYPTED ===\nSENDING CIPHER TEXT\n"
                       + new String());
    // Base 64 encode the cipher text
    byte[] b64_cipherText = Base64.getEncoder().encode(cipherBytes);
    toServer.writeBytes(new String(b64_cipherText)); 
    toServer.flush();


    // === RSA BASED SECRET EXCHANGE ===
    // 1. Generate a new DES secret key
    // 2. encrypt the DES secret using the recipients public key
    // 3. Transmit the encrypted secret to the recipient
    // 4. await response encrypted with this client's public key
    // 5. decrypt response stating that message was received
    


    serverConnSock.close(); 
  }
}
