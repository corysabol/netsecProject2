import java.io.*;
import java.net.*;
import javax.crypto.*;
import java.nio.charset.*;
 
class TCPClient {
  public static void main(String argv[]) throws Exception {

    // instance of crypto helper
    Crypto DES = new Crypto();
    // set up the DES cypher
    DES.setCrypto(Crypto.CIPHER_ALGORITHM.DES);

    String clearText = "Network Security";
    byte[] clearBytes = clearText.getBytes();
    byte[] cipherBytes;
    String cipherText;

    //BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));

    // === SETUP SHARED KEY, DIFFIE-HELMAN NOT YET IMPLEMENTED ===
    // Just serialize the key and send it off so that the server
    // can unserizalize it and use it easily with the crypto lib?
    SecretKey sharedSecretKey = DES.getKeyGen().generateKey();
    byte[] keyEncoded = sharedSecretKey.getEncoded();
    System.out.println(new String(keyEncoded));  
    // init the cipher to encrypt  
    DES.getCipher().init(DES.getCipher().ENCRYPT_MODE, sharedSecretKey);

    // === PERFORM DES ENCRYPTION ON MESSAGE ===
    cipherBytes = DES.getCipher().doFinal(clearBytes);
    cipherText = new String(cipherBytes, StandardCharsets.UTF_8); // Encode the message with UTF-8

    /*
    Socket serverConnSock = new Socket("localhost", 6789);
    DataOutputStream toServer = new DataOutputStream(serverConnSock.getOutputStream());
    //BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
    
    toServer.writeBytes(cipherText);
    
    serverConnSock.close();
    */

  }
}
