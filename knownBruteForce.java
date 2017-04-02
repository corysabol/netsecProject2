import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;


public class knownBruteForce {
	
	public static byte[] key;
	
	public static void keyGen()
	{
		for(int c=0;c<key.length;c++)
		{
			key[c]++;
			if(key[c]!=0)
				break;
		}
	}
	//increments the key by one each time the method is called
	
	public static void brute(String pt, String ct) 
	{
		try{
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DES"));
			String testDecrypt = new String(cipher.doFinal(ct.getBytes()));
			while(pt!=testDecrypt)
			{
				keyGen();
		    	cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DES"));
		    	testDecrypt = new String(cipher.doFinal(ct.getBytes()));
			}
			//continually tries keys until there is a match
		}
		catch(Exception e)
		{
			System.out.println(e);
		}
	}
	
	public static void main(String args[])
	{
		key = new byte[8];
		String[] plainText = new String[10000];
		String[] cipherText = new String[10000];
		//Set to input from text files to these arrays
		
		for(int c=0;c<10000;c++)
		{
			brute(plainText[c],cipherText[c]);
		}
		//goes through all of the plain/ciphertext pairs
		
		System.out.println("This is the key: "+new String(key));
	}
}
