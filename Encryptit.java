package enc;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.Set;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryptit {

	private static String secKey="abcdefghijklmnop";
	private static String salt="123456789";
	
	private static void listCiphersAvailable() {
		Vector<String> algs=new Vector<String>();
		Vector<String> otherTypes=new Vector<String>();
		Provider provs[] = Security.getProviders();
		for (Provider prv:provs) {
			Set<Service> svcs=prv.getServices();
			for (Service svc:svcs) { 
				if ("Cipher".equals(svc.getType())) {
					algs.add(svc.getAlgorithm());
				} else {
					StringBuffer set=new StringBuffer(svc.getType());
					if (svc.getAlgorithm()!=null && svc.getAlgorithm().length()>0) {
						set.append(":").append(svc.getAlgorithm());
					}
					if (!otherTypes.contains(set.toString())) {
						otherTypes.add(set.toString());
					}
				}
			}
		}
		String ary[]=algs.toArray(new String[algs.size()]);
		Arrays.sort(ary);
		System.out.println("##########################################");
		System.out.println("Listing Algorithms for Cipher:");
		for (String alg:ary) {
			System.out.println(alg);
		}
		ary=otherTypes.toArray(new String[otherTypes.size()]);
		Arrays.sort(ary);
		System.out.println("##########################################");
		System.out.println("Listing other types for Providers:");
		for (String oth:ary) {
			System.out.println(oth);
		}
		
	}
	private static SecretKeySpec setupKeySpec(int which) throws Exception {
		SecretKeyFactory factory=null;
		switch (which) {
		case 0:
			factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");break;
		case 1:
			factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA224");break;
		case 2:
			factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");break;
		case 3:
			factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384");break;
		case 4:
			factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");break;
		default:
			factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");break;
		}
		
		KeySpec spec=new PBEKeySpec(secKey.toCharArray(),salt.getBytes(),65536,256);
		SecretKey tmp=factory.generateSecret(spec);
		SecretKeySpec secretKeySpc=new SecretKeySpec(tmp.getEncoded(),"AES");
		
		return secretKeySpc;
	}
	private static Cipher getCipherInst() throws Exception {
		return Cipher.getInstance("AES/CBC/NoPadding");
	}
	public static String encrypt(String toEnc,String sec,int which) {
		try {
			byte[] iv= {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
			IvParameterSpec ivspec=new IvParameterSpec(iv);
			
			SecretKeySpec secretKeySpc=setupKeySpec(which);
			
			Cipher ciph=getCipherInst();
			ciph.init(Cipher.ENCRYPT_MODE,secretKeySpc,ivspec);
//			Provider prv=ciph.getProvider();
//			Set<Service> svcs = prv.getServices();
			byte bits[]=toEnc.getBytes("UTF-8");
			return Base64.getEncoder().encodeToString(ciph.doFinal(bits));
		} catch (Exception err) {
			err.printStackTrace();
		}
		return null;
	}
	public static String decrypt(String toDec,String sec,int which) {
		try {
			byte[] iv= {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
			IvParameterSpec ivspec=new IvParameterSpec(iv);
			
			SecretKeySpec secretKeySpc=setupKeySpec(which);
			
			Cipher ciph=getCipherInst();
			ciph.init(Cipher.DECRYPT_MODE,secretKeySpc,ivspec);
			return new String(ciph.doFinal(Base64.getDecoder().decode(toDec)));
		} catch (Exception err) {
			err.printStackTrace();
		}
		return null;
	}
//	public static void hashValue(String[] stringData) {
//		Scanner sn=new Scanner(System.in);
//		System.out.println("Please enter data for which SHA256 is required:");
//		String data=sn.nextLine();
//		MessageDigest digest=MessageDigest.getInstance("SHA-256");
//		byte[] hash=digest.digest(stringData.getBytes("UTF-8"));
//	}
	
	public static final String testEncVal1="The quick brown fox jumped over the lazy dog.";
	public static final String testEncVal2=
			"What do you do with a drunken sailor, "+
			"early in the morning. "+
			"weigh hey and up she rises, "+
			"shave his belly with a rusty razor, "+
			"keel-haul him until he's sober, "+
			"put him in a row boat with the Captain's daughter, ";
	private static String to16BlockLength(String txt) {
		StringBuffer buf=new StringBuffer(txt);
		while((buf.length()%16)>0) {
			buf.append("#");
		}
		return buf.toString();
	}
	public static void main(String args[]) {
		listCiphersAvailable();
		runTest(testEncVal1);
		System.out.println("############################");
		runTest(testEncVal2);
		byte allBytes[]=new byte[256];
		for (int i=0; i<allBytes.length; i++) {
			allBytes[i]=(byte)i;
		}
		System.out.println(Base64.getEncoder().encodeToString(allBytes));
	}
	private static void runTest(String test) {
		System.out.printf("Before padding: %s\n",test);
		String testEnc=to16BlockLength(test);
		int w=-1;
//		for (int w=0; w<5; w++) {
			System.out.printf("Encrypting: %s\n",testEnc);
			String enc=encrypt(testEnc, secKey,w);
			System.out.printf("Encrypted text: %s\n", enc);
			System.out.printf("Encrypted text length: %d\n", enc.length());
			String dec=decrypt(enc, secKey,w);
			System.out.printf("Decrypted text: %s\n",dec);
			if (testEnc.equals(dec)) {
				System.out.println("Text-to-encrypt == decrypted-text");
			} else {
				System.err.println("Encryption to decryption chain didn't work");
			}
//		}
	}
}
