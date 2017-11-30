package com.acko.enc;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
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
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class AckoEncApp {

	private Cipher cipher;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public AckoEncApp() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
	public PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(keyBytes));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(keyBytes));
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

	public static void main(String[] args) throws Exception {
		if (!(new File("KeyPair/privateKey.pem").exists()
				&& new File("KeyPair/publicKey.pem").exists())) {
			System.out.println("Generate key-pair first.");
			System.exit(1);
		}
		AckoEncApp ac = new AckoEncApp();
		PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey.pem");
		PublicKey publicKey = ac.getPublic("KeyPair/publicKey.pem");
		String msg = "Acko Confidential Message!";
		String signature = ac.signMessage(msg, privateKey);
		boolean varified = ac.verifyMessage(msg, signature, publicKey);

		System.out.println("Original Message: " + msg
			+  "\nMessage Signature: " + signature
			+ "\nSignature Varified: " + varified);
	}
}