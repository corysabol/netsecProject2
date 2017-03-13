import java.io.*;
import java.net.*;
 
class TCPClient {
  public static void main(String argv[]) throws Exception {

    // instance of crypto helper
    Crypto DES = new Crypto();
    // set up the DES cypher
    DES.setCrypto(Crypto.CIPHER_ALGORITHM.DES);

    String sentence;
    String modifiedSentence;
    BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));
    Socket clientSocket = new Socket("localhost", 6789);
    DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
    BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
    
    sentence = inFromUser.readLine();
    outToServer.writeBytes(sentence + '\n');
    modifiedSentence = inFromServer.readLine();
    System.out.println("FROM SERVER: " + modifiedSentence);
    
    clientSocket.close();

  }
}
