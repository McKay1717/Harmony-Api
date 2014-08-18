package net.mckay1717.util;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
/**
 * 
 * @author Nicolas .I (McKay1717)
 *
 */
public class Security {

	/**
	 * 
	 * @param convertme
	 * @return Encoded string in SHA1
	 */
	public static String toSHA1(byte[] convertme) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		}
		catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		return new String(md.digest(convertme));
	}
	public static String byteArrayToHexString(byte[] b) {
		String result = "";
		for (int i=0; i < b.length; i++) {
			result +=
					Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
		}
		return result;
	}
	/**
	 * 
	 * @param password String to encode in MD5
	 * @return the encoded String
	 */

	public static String encode(String password)
	{
		byte[] uniqueKey = password.getBytes();
		byte[] hash      = null;

		try
		{
			hash = MessageDigest.getInstance("MD5").digest(uniqueKey);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new Error("No MD5 support in this VM.");
		}

		StringBuilder hashString = new StringBuilder();
		for (int i = 0; i < hash.length; i++)
		{
			String hex = Integer.toHexString(hash[i]);
			if (hex.length() == 1)
			{
				hashString.append('0');
				hashString.append(hex.charAt(hex.length() - 1));
			}
			else
				hashString.append(hex.substring(hex.length() - 2));
		}
		return hashString.toString();
	}

	public void setTrustAllSslCertificates() throws Exception {
		TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}
			public void checkClientTrusted(X509Certificate[] certs, String authType) {
			}
			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}
		}
		};

		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	}
	
	/***
	 *  Copy of uniqid in php http://php.net/manual/fr/function.uniqid.php
	 * @param prefix
	 * @param more_entropy
	 * @return
	 */
	public String uniqid(String prefix,boolean more_entropy)
	{
		long time = System.currentTimeMillis();
		//String uniqid = String.format("%fd%05f", Math.floor(time),(time-Math.floor(time))*1000000);
		//uniqid = uniqid.substring(0, 13);
		String uniqid = "";
		if(!more_entropy)
		{
			uniqid = String.format("%s%08x%05x", prefix, time/1000, time);
		}else
		{
			SecureRandom sec = new SecureRandom();
			byte[] sbuf = sec.generateSeed(8);
			ByteBuffer bb = ByteBuffer.wrap(sbuf);

			uniqid = String.format("%s%08x%05x", prefix, time/1000, time);
			uniqid += "." + String.format("%.8s", ""+bb.getLong()*-1);
		}


		return uniqid ;
	}

}
