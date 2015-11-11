package org.certificatetransparency.smime.certificateauthority;

import java.io.InputStream;
import java.util.Date;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.IOException;
import java.net.Socket;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class ClientHandler implements Runnable {
	private Socket clientSocket;

	static private String certificateTransparencyIp;
	static private PrivateKey certificateAuthorityPrivateKey;
	static private X509Certificate certificateAuthorityCertificate;
	static private String organizationUnit;
	static private String organization;
	static private String country;
	static private String state;
	static private String city;

	static void loadData(String certificateTransparencyIp, String CertificateCAPath, String PrivateKeyCAPath,
			String organizationUnit, String organization, String country, String state, String city) {
		certificateAuthorityCertificate = loadCaCertificate(CertificateCAPath);
		certificateAuthorityPrivateKey = readPrivateKey(PrivateKeyCAPath);
		
		if(certificateAuthorityCertificate==null || certificateAuthorityPrivateKey==null )
			return;

		ClientHandler.certificateTransparencyIp = certificateTransparencyIp;
		ClientHandler.organizationUnit = organizationUnit;
		ClientHandler.organization = organization;
		ClientHandler.country = country;
		ClientHandler.state = state;
		ClientHandler.city = city;
	}

	public ClientHandler(Socket clientSocket, String certificateTransparencyIp) {
		this.clientSocket = clientSocket;
	}

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
			Security.addProvider(new BouncyCastleProvider());
	}

	static private X509Certificate loadCaCertificate(String certificatePath) {
		FileInputStream fileInputStream = null;
		Certificate cert = null;
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			fileInputStream = new FileInputStream(certificatePath);
			cert = certificateFactory.generateCertificate(fileInputStream);
		} catch (CertificateException e) {
			e.printStackTrace();
			try {
				fileInputStream.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return (X509Certificate) cert;
	}

	static private PrivateKey readPrivateKey(String privateKeyPath) {
		try {
			RandomAccessFile randomAccessFile = new RandomAccessFile(privateKeyPath, "r");
			byte[] buf = new byte[(int) randomAccessFile.length()];
			randomAccessFile.readFully(buf);
			randomAccessFile.close();
			PKCS8EncodedKeySpec keySpecification = new PKCS8EncodedKeySpec(buf);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePrivate(keySpecification);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * https://github.com/google/certificate-transparency
	 * JSON-encodes the list of certificates into a JSON object.
	 * 
	 * @param certs
	 *            Certificates to encode.
	 * @return A JSON object with one field, "chain", holding a JSON array of
	 *         base64-encoded certificates.
	 */
	@SuppressWarnings("unchecked") // Because JSONObject, JSONArray extend raw
									// types.
	JSONObject encodeCertificates(List<Certificate> encryptionChainCertificate,
			List<Certificate> signatureCertificate,String email) {
		JSONArray jsonEncryptionCertificate = new JSONArray();
		JSONArray jsonSignatureCertificate = new JSONArray();
		try {
			for (Certificate cert : encryptionChainCertificate)
				jsonEncryptionCertificate.add(Base64.encodeBase64String(cert.getEncoded()));
			for (Certificate cert : signatureCertificate)
				jsonSignatureCertificate.add(Base64.encodeBase64String(cert.getEncoded()));
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("encryptionCertificate", jsonEncryptionCertificate);
		jsonObject.put("signatureCertificate", jsonSignatureCertificate);
		jsonObject.put("email", email);
		return jsonObject;
	}

	/**
	 * https://github.com/google/certificate-transparency
	 * Make an HTTP POST method call to the given URL with the provided JSON
	 * payload.
	 * 
	 * @param url
	 *            UmakePostRequestRL for POST method
	 * @param jsonPayload
	 *            Serialized JSON payload.
	 * @return Server's response body.
	 */
	public String makePostRequest(String url, String jsonPayload) {
		try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
			HttpPost post = new HttpPost(certificateTransparencyIp);
			post.setEntity(new StringEntity(jsonPayload, "utf-8"));
			post.addHeader("Content-Type", "application/json; charset=utf-8");
			return httpClient.execute(post, new BasicResponseHandler());
		} catch (IOException e) {
			return null;
		}
	}

	private PublicKey Frombase64toPublicKey(String encodePublicKey) {
		PublicKey publicKey = null;
		try {
			byte[] publicKeyBytes = Base64.decodeBase64(encodePublicKey.getBytes());
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return publicKey;
	}

	/**
	 * Build a V3 certificate
	 */
	private List<Certificate> generateV3Certificate(PublicKey publicKey, String email, String commonName) {
		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.CN, commonName);
		nameBuilder.addRDN(BCStyle.OU, organizationUnit);
		nameBuilder.addRDN(BCStyle.O, organization);
		nameBuilder.addRDN(BCStyle.C, country);
		nameBuilder.addRDN(BCStyle.ST, state);
		nameBuilder.addRDN(BCStyle.L, city);
		nameBuilder.addRDN(BCStyle.EmailAddress, email);

		X509Certificate cert = null;
		try {
			X500Principal principal = new X500Principal(nameBuilder.build().getEncoded());
			X509Certificate caCert = (X509Certificate) certificateAuthorityCertificate;
			BigInteger serialNumber = BigInteger.valueOf(Math.abs(SecureRandom.getInstance("SHA1PRNG").nextInt()));
			int VALIDITY_PERIOD = 3650 * 24 * 60 * 60 * 1000;
			X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(caCert.getSubjectX500Principal(),
					serialNumber, new Date(System.currentTimeMillis()),
					new Date(System.currentTimeMillis() + VALIDITY_PERIOD), principal, publicKey);
			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			certBldr.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(caCert))
					.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey))
					.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC")
					.build(certificateAuthorityPrivateKey);
			cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBldr.build(signer));

		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		List<Certificate> chaincertificate = new ArrayList<>();
		chaincertificate.add((Certificate) cert);
		chaincertificate.add(certificateAuthorityCertificate);
		return chaincertificate;
	}
	
	 private byte[] postCertificateToLogServer(String jsonCertificate) {
		  PrintWriter printWriter =null; 
		  Socket socket =null;
		 try {
			 socket = new Socket("localhost", 7777);
			 printWriter = new PrintWriter(socket.getOutputStream(), true);
			 printWriter.flush();
			 printWriter.println(jsonCertificate);                                  
	            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
	            byte[] message=null;
	            int length = dataInputStream.readInt();                    
	            if(length>0) {
	                message = new byte[length];
	                dataInputStream.readFully(message, 0, message.length); 
	                dataInputStream.close();
	            }           
	           return message;

	        } catch (Exception e) {
	            e.printStackTrace();
	           return null;
	        }
	          finally {        	
	        	try {
	        		printWriter.close();
	        		socket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
	
			}
	    }

	
	public static void writeCertificateToFile(final Certificate[] certificate,String outputCertificateFile)
			throws Exception {
		final FileOutputStream certOutputStream = new FileOutputStream(
				outputCertificateFile);
		PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(
				certOutputStream));
		pemWrt.writeObject(certificate[0]);
		pemWrt.writeObject(certificate[1]);
		pemWrt.close();
	}
	

	public void run() {
		InputStream input = null;
		OutputStream output = null;
		try {
			input = clientSocket.getInputStream();
			output = clientSocket.getOutputStream();
			BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			String jsonInput = in.readLine();
			System.out.println("Server:" + jsonInput);
			JSONParser parser = new JSONParser();
			Object obj = parser.parse(jsonInput);
			JSONObject obj2 = (JSONObject) (obj);

			String commonName = (String) obj2.get("LastName") + " " + (String) obj2.get("FirstName");
			String email = (String) obj2.get("email");
			PublicKey encryptionPublicKey = Frombase64toPublicKey((String) obj2.get("encryptionPublicKey"));
			PublicKey signaturePublicKey = Frombase64toPublicKey((String) obj2.get("signaturePublicKey"));
			List<Certificate> encryptionChainCertificate = generateV3Certificate(encryptionPublicKey, email,
					commonName);
			final	Certificate[] smimeCertificate = new Certificate[2];
	    	smimeCertificate[0] =encryptionChainCertificate.get(0) ;
		    smimeCertificate[1] = encryptionChainCertificate.get(1);
		    
		    List<Certificate> signatureChainCertificate = generateV3Certificate(signaturePublicKey, email, commonName);
		    final	Certificate[] smimeCertificate1 = new Certificate[2];
	    	smimeCertificate1[0] =encryptionChainCertificate.get(0) ;
		    smimeCertificate1[1] = encryptionChainCertificate.get(1);
	

		    try {
				writeCertificateToFile(smimeCertificate,"test1.pem");
				writeCertificateToFile(smimeCertificate1,"test2.pem");

			} catch (Exception e) {
				e.printStackTrace();
			}
			
			JSONObject jsonSMIMECertificate = encodeCertificates(encryptionChainCertificate, signatureChainCertificate,email);
			byte[] response=postCertificateToLogServer(jsonSMIMECertificate.toJSONString());
			DataOutputStream dataOutputStream = new DataOutputStream(output);
			dataOutputStream.writeInt(response.length);
			dataOutputStream.write(response); 
			dataOutputStream.flush();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		} finally {
			try {
				if (output != null)
					output.close();
				if (input != null)
					input.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
}
