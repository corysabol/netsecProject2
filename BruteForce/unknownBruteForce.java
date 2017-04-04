import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class unknownBruteForce {
	public static byte[] key;
	public static double[][] frequencyRange = {{0.0762,0.0862},{0.0099,0.0199},{0.0221,0.0321},{0.0382,0.0482},{0.1152,0.1252},{0.0180,0.0280},{0.0153,0.0253},{0.0542,0.0642},{0.0681,0.0781},{0,0.0060},{0.0019,0.0119},{0.0348,0.0448},{0.0211,0.0311},{0.0645,0.0745},{0.0718,0.0818},{0.0132,0.0232},{0,0.0061},{0.0552,0.0652},{0.0578,0.0678},{0.0860,0.0960},{0.0238,0.0338},{0.0061,0.0161},{0.0159,0.0259},{0,0.0067},{0.0161,0.0261},{0,0.0057}};
	//Based off of this table: https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
	
	
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
	
	public static boolean brute(String ct[]) 
	{
		int[] letterDist = new int[26];
		int totalLetters = 0;
		boolean english = true;
		try{
			for(int c=0;c<ct.length;c++)
			{
				Cipher cipher = Cipher.getInstance("DES");
				cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DES"));
				String decrypt = new String(cipher.doFinal(ct[c].getBytes()));
				for(int d=0;d<decrypt.length();d++)
				{
					letterDist[Character.toLowerCase(decrypt.charAt(d))-'a']++;
					totalLetters++;
				}
			}
			for(int c=0;c<letterDist.length;c++)
			{
				double percentage = letterDist[c]/totalLetters;
				if(percentage<frequencyRange[c][0]||percentage>frequencyRange[c][1])
					english=false;
			}
			//Checks frequency of each letter within .5 percent of the table value
			return english;
		}
		catch(Exception e)
		{
			System.out.println(e);
			return false;
		}
	}
	
	public static void main(String args[])
	{
		key = new byte[8];
		byte max = (byte) 256;
		byte[] maxKey = new byte[8];
		Arrays.fill(maxKey, max);
		String[] cipherText = new String[10000];
		//Set to input from text file to array
		ArrayList possibleKeys = new ArrayList<byte[]>();
		
		while(!key.equals(maxKey))
		{
			if(brute(cipherText))
				possibleKeys.add(key);
			keyGen();
		}
		/*
		 * Goes through all of the possible keys. Keys that work are added
		 * to the ArrayList possibleKeys.
		 */
		
		System.out.println("This is the key: "+new String(key));
	}
}
