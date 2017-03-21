import java.io.*;
import java.net.*;
import java.util.Random;

class TCPClient
{
	static int modulus;
	static int base; 
	static int secret=new Random().nextInt();
	static int sharedSecret;

	public static String diffieHellman(String sentence) throws Exception
	{
		if(!sentence.equals("Enter an Int"))
		{
			if(modulus==0)
				modulus=Integer.parseInt(sentence);
			else if(base==0)
			{
				base=Integer.parseInt(sentence);
				return String.valueOf((int) Math.pow(base,secret)%modulus);
			}
			else
				sharedSecret = (int) Math.pow(Integer.parseInt(sentence),secret)%modulus;
		}	
		return "";
	}
	public static void main(String argv[]) throws Exception
	    {
		    String sentence;
		    String modifiedSentence;
		    modulus=0;
		    base=0;
	            sharedSecret=0;
		    while(true)
		    {
			    BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));
			    Socket clientSocket = new Socket("localhost", 6789);
			    DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
			    BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				
			    sentence = inFromUser.readLine();
			    outToServer.writeBytes(sentence + '\n');
			    String returnedSentence = inFromServer.readLine();
			    if(sharedSecret==0)
			    {
				String computed = diffieHellman(returnedSentence);
				System.out.println("FROM SERVER: "+ returnedSentence);
				if(!computed.equals(""))
				{
					clientSocket = new Socket("localhost", 6789);
				        outToServer = new DataOutputStream(clientSocket.getOutputStream());
				        inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
					outToServer.writeBytes(computed+'\n');
					returnedSentence = inFromServer.readLine();
					diffieHellman(returnedSentence);
				}
			    }
			    else
			    {
			    	System.out.println("FROM SERVER: " + returnedSentence);
			    }
	    	    }
	    }
}
