package net.mckay1717;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status.Family;

import net.mckay1717.util.Security;

import org.json.simple.JSONValue;

import sun.misc.BASE64Encoder;
/***
 * 
 * @author Nicolas I. (McKay1717)
 *
 */
public class HarmonyApiRequest {

	/***
	 * Some variable
	 */
	protected String username = "";
	protected String password ="";
	protected boolean use_ssl = false;
	private final String ApiHostName = "api.harmony-hosting.com";


	/**
	 * Constructor (Setup the variable of the instance of this class)
	 * @param username username on Harmonyhosting
	 * @param password this is the Api Key
	 * @param use_ssl if the request will be encrypted
	 * 
	 **/	
	public HarmonyApiRequest(String username, String password, boolean use_ssl)
	{
		if(username.isEmpty() || password.isEmpty())
		{
			return;
		}
		else
		{
			this.username = username;
			this.password = password;
			this.use_ssl = use_ssl;

		}
	}


	/**
	 * Build the request token
	 * @param passwordDigest
	 * @param nonceHigh
	 * @param created
	 * @return The Tokens
	 */
	private String tokens(String passwordDigest,String nonceHigh,String created)
	{
		return "UsernameToken Username=\""+this.username+"\", PasswordDigest=\""+passwordDigest+"\", Nonce=\""+nonceHigh+"\", Created=\""+created+"\"";
	}

	private String call(String method,String url,  @SuppressWarnings("rawtypes") Map body) throws Exception
	{

		Security sec = new Security();
		sec.setTrustAllSslCertificates();
		/**
		 * Build URL
		 */
		String proto = "http://";

		if(this.use_ssl)
		{
			proto = "https://";
		}
		/**
		 * Get CurrentDate & convert to ISO8601 
		 */

		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
		String Created = df.format(new Date());


		/**
		 * Create The auth token
		 */
		@SuppressWarnings("static-access")
		String nonce = sec.encode(sec.uniqid("nonce_", true)) ;
		nonce = nonce.substring(0, 16);
		BASE64Encoder enc = new sun.misc.BASE64Encoder();
		String nonceHigh = enc.encode(nonce.getBytes());
		@SuppressWarnings("static-access")
		String passwordDigestBeforeEncoding = sec.toSHA1((nonce+Created+this.password).getBytes());
		String passwordDigest = enc.encode(passwordDigestBeforeEncoding.getBytes());
		String token = this.tokens(passwordDigest, nonceHigh, Created);


		Client client = ClientBuilder.newClient();
		WebTarget target = client.target(proto+this.ApiHostName).path(url);

		Response response = null ;


		switch (method)
		{
		case "GET": response = target.request(MediaType.APPLICATION_JSON_TYPE).header("X-WSSE:", token).get();; break;
		case "PUT":  response = target.request(MediaType.APPLICATION_JSON_TYPE).header("X-WSSE:", token).put(Entity.json(JSONValue.toJSONString(body))); break;
		case "POST":  response = target.request(MediaType.APPLICATION_JSON_TYPE).header("X-WSSE:", token).post(Entity.json(JSONValue.toJSONString(body))); break;
		case "DELETE":  response = target.request(MediaType.APPLICATION_JSON_TYPE).header("X-WSSE:", token).method("DELETE", Entity.json(JSONValue.toJSONString(body))); break;
		}



		if (response.getStatusInfo().getFamily() == Family.SUCCESSFUL) {
			return (response.readEntity(String.class) );
		} else {
			return ("ERROR! " + response.getStatus() + " " + response.readEntity(String.class));    
		}



	}

	/**
	 * GET
	 * @throws Exception 
	 */
	@SuppressWarnings("rawtypes")
	public String get(String url) throws Exception {
		return this.call("GET", url, new HashMap());
	}
	/**
	 * PUT
	 * @throws Exception 
	 */
	public String put(String url, @SuppressWarnings("rawtypes") Map body) throws Exception {
		return this.call("PUT", url, body);
	}

	/**
	 * POST
	 * @throws Exception 
	 */
	public String post(String url, @SuppressWarnings("rawtypes") Map body) throws Exception {
		return this.call("POST", url, body);
	}

	/**
	 * DELETE
	 * @throws Exception 
	 */
	public String delete(String url, @SuppressWarnings("rawtypes") Map body) throws Exception {
		return this.call("DELETE", url, body);
	}


}
