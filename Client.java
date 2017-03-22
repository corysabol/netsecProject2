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
    Crypto encrypter = new Crypto();
    // set up the DES cypher
    encrypter.setCrypto(Crypto.CIPHER_ALGORITHM.DES);
    SecretKey DH_DESSecret = null;

    String clearText = "Network Security";
    byte[] clearBytes = clearText.getBytes();
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
    //BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

    // === DIFFIE HELLMAN: 1 ===
    String dhParams = encrypter.generateDHParams();
    // === DIFFIE HELLMAN: 2 ===
    toServer.writeBytes(dhParams); 
    // === DIFFIE HELLMAN: 3 ===
    // generate this client's keypair
    KeyPair kp = encrypter.DH_genKeyPair(dhParams);
    // === DIFFIE HELLMAN: 4 ===
    // Assuming the server generated it's keypair the public key of the server
    // will be located at keys/server/dh_public for the sake of simplicity.
    byte[] otherPubkBytes = null;
    try {
      // will relative path work?
      Path path = Paths.get("keys/server/dh_public");
      otherPubkBytes = Files.readAllBytes(path);

      // === DIFFIE HELLMAN: 5 ===
      DH_DESSecret = encrypter.DH_genDESSecret(kp.getPrivate(), otherPubkBytes);
    } catch (FileNotFoundException e) {}


    // === MESSAGING PHASE ===
    
    //toServer.writeBytes(cipherText);
    serverConnSock.close();

  }
}
