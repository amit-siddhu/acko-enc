package com.acko.enc;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;

import org.json.JSONObject;

public class AckoEncApp {

	public static final String API_URL = "https://shire.acko.com/api";
	private Cipher cipher;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public AckoEncApp() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
	public PrivateKey getPrivate(String filename) throws Exception {
		PemReader reader = new PemReader(Files.newBufferedReader(new File(filename).toPath()));
		PemObject pemObject = reader.readPemObject();
        reader.close();
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemObject.getContent());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
	public PublicKey getPublic(String filename) throws Exception {
		PemReader reader = new PemReader(Files.newBufferedReader(new File(filename).toPath()));
		PemObject pemObject = reader.readPemObject();
        reader.close();
		X509EncodedKeySpec spec = new X509EncodedKeySpec(pemObject.getContent());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public String signMessage(String msg, PrivateKey key) throws Exception {
		Signature privateSignature = Signature.getInstance("SHA256WithRSA/PSS", "BC");
		MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec("SHA-256");
		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec , 16, 1);
		privateSignature.setParameter(pssParameterSpec);
		privateSignature.initSign(key);
		privateSignature.update(msg.getBytes("UTF-8"));
	    byte[] signature = privateSignature.sign();
		return Base64.getEncoder().encodeToString(signature);
	}

	public boolean verifyMessage(String msg, String signature, PublicKey key) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256WithRSA/PSS", "BC");
		MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec("SHA-256");
		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec , 16, 1);
		publicSignature.setParameter(pssParameterSpec);
		publicSignature.initVerify(key);
		publicSignature.update(msg.getBytes("UTF-8"));
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		return publicSignature.verify(signatureBytes);
	}

	public String callApi(String requestData, String resourcePath) throws Exception {
		URL url = new URL(API_URL+resourcePath);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Content-Type","application/json");
		con.setInstanceFollowRedirects(false);

		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(requestData);
		wr.flush();
		wr.close();

		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		StringBuffer response = new StringBuffer();

		String output;
		while ((output = in.readLine()) != null) {
			response.append(output);
		}
		in.close();

		return response.toString();
	}

	public Map createPackage(String b64msg, String signature) {
		Map<String, String> map = new HashMap<>();
		map.put("msg", b64msg);
		map.put("sig", signature);
		return map;
	}

	public Map book() {
		Map<String, String> map = new HashMap<>();
		map.put("key", "ola_secret");
		map.put("name", "Amit Upadhyay");
		map.put("phone", "9820715512");
		map.put("cid", "1");
		map.put("trip_id", "124");
		map.put("traveler_name", "Amit Upadhyay");
		map.put("traveler_phone", "9820715512");
		map.put("ride_type", "a");
		map.put("category", "1");
		map.put("booked_on", Instant.now().toString());
		return map;
	}

	public Map view() {
		Map<String, String> map = new HashMap<>();
		map.put("key", "ola_secret");
		map.put("trip_id", "123");
		map.put("booked_on", Instant.now().toString());
		return map;
	}

	public Map cancel() {
		Map<String, String> map = new HashMap<>();
		map.put("key", "ola_secret");
		map.put("trip_id", "123");
		map.put("cancelled_on", Instant.now().toString());
		return map;
	}

	public static void main(String[] args) throws Exception {

		if (!(new File("KeyPair/privateKey.pem").exists()
				&& new File("KeyPair/publicKey.pem").exists())) {
			System.out.println("Generate key-pair first.");
			System.exit(1);
		}

		AckoEncApp ac = new AckoEncApp();
		PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey.pem");
		PublicKey publicKey = ac.getPublic("KeyPair/publicKey.pem");

		Map dataMap = ac.book();
		JSONObject jsonData = new JSONObject(dataMap);

		String msg = jsonData.toString();
		String signature = ac.signMessage(msg, privateKey);
		String b64msg = Base64.getEncoder().encodeToString(msg.getBytes());

		Map requestMap = ac.createPackage(b64msg, signature);
		String requestData = new JSONObject(requestMap).toString();

		String resourcePath = "/ola_trip_booked";

		System.out.println("Original Message: " + msg
			+  "\nEncoded Message: " + b64msg
			+  "\nMessage Signature: " + signature
			+  "\nRequest Data: " + requestData);

		String response = ac.callApi(requestData, resourcePath);
		System.out.println("\nResponse: " + response);
	}
}