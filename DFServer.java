import java.io.*; 
import java.net.*; 
import java.util.Random;

class TCPServer 
{
	static int modulus;
	static int base; 
	static int secret=new Random().nextInt();
	static int sharedSecret;

	public static String diffieHellman(String clientSentence) throws Exception
	{
		//The first number recieved should be the modulus
		//The second number recieved should be the base
		if(base==0)
		{
			try
			{
				if(modulus==0)
					modulus=Integer.parseInt(clientSentence);
				else if(base==0)
					base=Integer.parseInt(clientSentence);
				return clientSentence;
			}
			catch(NumberFormatException x)
			{
				return "Enter an Int";
			}
		}
		else
		{
			//the last number recieved should be the "encryted" value using the secret and the agreed numbers
			try
			{
				int computedVal = (int) Math.pow(base,secret)%modulus;
				int recieved = Integer.parseInt(clientSentence);
				sharedSecret = (int) Math.pow(recieved,secret)%modulus;
				return String.valueOf(computedVal);
			}
			catch(NumberFormatException x)
			{
				return "Enter an Int";
			}
		}
	}

	public static void main(String argv[]) throws Exception 
	{ 
		String clientSentence; 
		String capitalizedSentence;
		modulus=0;
		base=0;
		sharedSecret=0;
		ServerSocket welcomeSocket = new ServerSocket(6789); 

		while(true) 
		{ 
			Socket connectionSocket = welcomeSocket.accept(); 
			BufferedReader inFromClient = 
				new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream()); 
			clientSentence = inFromClient.readLine(); 
			System.out.println("Received: " + clientSentence); 
			/*
			* Establishing the shared modulus and base numbers by taking input from the client
			*/
				
			if(sharedSecret==0)
			{
				outToClient.writeBytes(diffieHellman(clientSentence) + '\n');
			}
			else
			{
				capitalizedSentence = clientSentence.toUpperCase() + '\n'; 
				outToClient.writeBytes(capitalizedSentence); 
			}
		} 
		//welcomeSocket.close();
	} 
}
