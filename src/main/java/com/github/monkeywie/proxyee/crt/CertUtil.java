package com.github.monkeywie.proxyee.crt;

import com.github.monkeywie.proxyee.util.Log;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class CertUtil {
	private static final Base64.Encoder base64Encoder = Base64.getEncoder();

	private static KeyFactory keyFactory = null;
	static {
		//注册BouncyCastleProvider加密库
		Security.addProvider(new BouncyCastleProvider());
	}

	private static KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
		if (keyFactory == null) {
			keyFactory = KeyFactory.getInstance("RSA");
		}
		return keyFactory;
	}

	/**
	 * 生成RSA公私密钥对,长度为2048
	 */
	public static KeyPair genKeyPair() throws Exception {
		KeyPairGenerator caKeyPairGen = KeyPairGenerator.getInstance("RSA");
		caKeyPairGen.initialize(2048);
		return caKeyPairGen.genKeyPair();
	}

	/**
	 * 从文件加载RSA私钥 openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out
	 * ca_private.der
	 */
	public static PrivateKey loadPriKey(byte[] bts)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bts);
		return getKeyFactory().generatePrivate(privateKeySpec);
	}

	/**
	 * 从文件加载RSA私钥 openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out
	 * ca_private.der
	 */
	public static PrivateKey loadPriKey(String path) throws Exception {
		return loadPriKey(Files.readAllBytes(Paths.get(path)));
	}

	/**
	 * 从文件加载RSA私钥 openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out
	 * ca_private.der
	 */
	public static PrivateKey loadPriKey(URI uri) throws Exception {
		return loadPriKey(Paths.get(uri).toString());
	}

	/**
	 * 从文件加载RSA公钥 openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
	 */
	public static PublicKey loadPubKey(byte[] bts) throws Exception {
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bts);
		return getKeyFactory().generatePublic(publicKeySpec);
	}

	/**
	 * 从文件加载RSA公钥 openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
	 */
	public static PublicKey loadPubKey(String path) throws Exception {
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get(path)));
		return getKeyFactory().generatePublic(publicKeySpec);
	}
   
	public static PrivateKey generatePrivateKey(String filename) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		return generatePrivateKey(null, filename);
	}
    
  
	public static PrivateKey generatePrivateKey(KeyFactory factory, String filename)
			throws InvalidKeySpecException, FileNotFoundException, IOException, NoSuchAlgorithmException {
		if (factory == null) {
			factory = getKeyFactory();
		}
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}

  
	public static PublicKey generatePublicKey(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException,  IOException {
		return generatePublicKey(null, filename);
	}
	
	public static PublicKey generatePublicKey(KeyFactory factory, String filename)
			throws InvalidKeySpecException, FileNotFoundException, IOException, NoSuchAlgorithmException {
		if (factory == null) {
			factory = getKeyFactory();
		}
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
		return factory.generatePublic(pubKeySpec);
	}

  
	/**
	 * 从文件加载RSA公钥 openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
	 */
	public static PublicKey loadPubKey(URI uri) throws Exception {
		return loadPubKey(Paths.get(uri).toString());
	}

	/**
	 * 从文件加载RSA公钥 openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
	 */
	public static PublicKey loadPubKey(InputStream inputStream) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte[] bts = new byte[1024];
		int len;
		while ((len = inputStream.read(bts)) != -1) {
			outputStream.write(bts, 0, len);
		}
		inputStream.close();
		outputStream.close();
		return loadPubKey(outputStream.toByteArray());
	}

	/**
	 * 从文件加载证书
	 */
	public static X509Certificate loadCert(InputStream inputStream) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(inputStream);
	}

  
	/**
	 * 从文件加载证书
	 */
	public static X509Certificate loadCert(String path) throws Exception {
		return loadCert(new FileInputStream(path));
	}
    /**
     * 从文件加载RSA私钥 openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out
     * ca_private.der
     */
    public static PrivateKey loadPriKey(InputStream inputStream)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] bts = new byte[1024];
        int len;
        while ((len = inputStream.read(bts)) != -1) {
            outputStream.write(bts, 0, len);
        }
        inputStream.close();
        outputStream.close();
        return loadPriKey(outputStream.toByteArray());
    }

  
	/**
	 * 从文件加载证书
	 */
	public static X509Certificate loadCert(URI uri) throws Exception {
		return loadCert(Paths.get(uri).toString());
	}

  
	/**
	 * 读取ssl证书使用者信息
	 */
	public static String getSubject(InputStream inputStream) throws Exception {
		X509Certificate certificate = loadCert(inputStream);
		//读出来顺序是反的需要反转下
		List<String> tempList = Arrays.asList(certificate.getIssuerDN().toString().split(", "));
		return IntStream.rangeClosed(0, tempList.size() - 1)
				.mapToObj(i -> tempList.get(tempList.size() - i - 1)).collect(Collectors.joining(", "));
	}

 
	/**
	 * 读取ssl证书使用者信息
	 */
	public static String getSubject(X509Certificate certificate) throws Exception {
		//读出来顺序是反的需要反转下
		List<String> tempList = Arrays.asList(certificate.getSubjectX500Principal().toString().split(", "));
		return IntStream.rangeClosed(0, tempList.size() - 1)
				.mapToObj(i -> tempList.get(tempList.size() - i - 1)).collect(Collectors.joining(", "));
	}

  
	public static X500Name getCASubject(X509Certificate certificate) throws Exception {
		X500Name subject = new X509CertificateHolder(certificate.getEncoded()).getSubject();
		return subject;
	}

  
	public static String publicKeyToPem(PublicKey key) throws IOException {
		String type = "RSA PUBLIC KEY";
		return encodeToPem(key, type);
	}

  
	public static String privateKeyToPem(PrivateKey privateKey) throws IOException{
		String type = "RSA PRIVATE KEY";
		return encodeToPem(privateKey, type);
	}

  
	private static String encodeToPem(Key privateKey, String type) throws IOException {
		String encoded = base64Encoder.encodeToString(privateKey.getEncoded());
		return encodePem(type, encoded);
	}

 
	public static String certToPem(X509Certificate certificate) throws IOException, CertificateEncodingException {
		String encoded = base64Encoder.encodeToString(certificate.getEncoded());
		String type = "CERTIFICATE";
		return encodePem(type, encoded);
	}

	private static String encodePem(String type, String content) {
		StringBuilder sb = new StringBuilder(1024);
		sb.append("-----BEGIN ").append(type).append("-----\n");
		sb.append(content);
		sb.append("-----END ").append(type).append("-----");
		return sb.toString();
	}
  
	private static String encodePem(String type, byte[] bytes) {
		return encodePem(type, new String(bytes));
	}

	/**
	 * 动态生成服务器证书,并进行CA签授
	 *
	 * @param issuer 颁发机构
	 */
	public static X509Certificate genCert(X500Name issuer, PrivateKey caPriKey, PublicKey serverPubKey,
										  Date notBefore, Date notAfter,
										  String... hosts) throws Exception {
		/* String issuer = "C=CN, ST=GD, L=SZ, O=lee, OU=study, CN=ProxyeeRoot";
        String subject = "C=CN, ST=GD, L=SZ, O=lee, OU=study, CN=" + host;*/
		//根据CA证书subject来动态生成目标服务器证书的issuer和subject
		X500Name subjectName = getX500Name(hosts[0], "AnyProxy", "SH", "SH", "CN", "AnyProxy SSL Proxy");
		JcaX509v3CertificateBuilder jv3Builder = new JcaX509v3CertificateBuilder(issuer,
				//issue#3 修复ElementaryOS上证书不安全问题(serialNumber为1时证书会提示不安全)，避免serialNumber冲突，采用时间戳+4位随机数生成
				BigInteger.valueOf(System.currentTimeMillis() + (long) (Math.random() * 10000) + 1000),
				notBefore,
				notAfter,
				subjectName,
				serverPubKey);
		Log.debug("generate cert for subject {} issuer {}", subjectName, issuer);
		//SAN扩展证书支持的域名，否则浏览器提示证书不安全
		GeneralName[] generalNames = new GeneralName[hosts.length];
		for (int i = 0; i < hosts.length; i++) {
			generalNames[i] = new GeneralName(GeneralName.dNSName, hosts[i]);
		}

		GeneralNames subjectAltName = new GeneralNames(generalNames);
		jv3Builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
//		final JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
//		jv3Builder.addExtension(Extension.authorityKeyIdentifier, false, u.createAuthorityKeyIdentifier(caCert));
//		jv3Builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(serverPubKey.getEncoded()));
		jv3Builder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

		//SHA256 用SHA1浏览器可能会提示证书不安全
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(caPriKey);
		X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(jv3Builder.build(signer));
		return certificate;
	}

	public static void savePublishToPemFile(PublicKey key, String host) {
		File f = getCertSaveFile(host, "pub");
		if (f.exists()) {
			return;
		}
		try {
			String pem = publicKeyToPem(key);
			try (FileOutputStream os = new FileOutputStream(f)) {
				os.write(pem.getBytes());
			}
		} catch (Exception ex) {
			Log.error("write public key pem {} for host {} to fail", key, host);
		}
	}

	public static void savePrivateToDerFile(PrivateKey key, String host) {
		try {
			File f = getCertSaveFile(host, "der");
			if (f.exists()) {
				return;
			}
			try (FileOutputStream os = new FileOutputStream(f)) {
				os.write(key.getEncoded());
			}
		} catch (Exception ex) {
			Log.error("write private key to der {} for host {} to fail", key, host);
		}
	}

	public static void savePrivateToFile(PrivateKey key, String host) {
		try {

			File f = getCertSaveFile(host, "key");
			if (f.exists()) {
				return;
			}
			String pem = privateKeyToPem(key);
			try (FileOutputStream os = new FileOutputStream(f)) {
				os.write(pem.getBytes());
			}
		} catch (Exception ex) {
			Log.error("write private key to pem {} for host {} to fail", key, host);
		}
	}

	public static void saveToFile(X509Certificate certificate, String host) {
		try {
			File f = getCertSaveFile(host, "crt");
			if (f.exists()) return;
			String pem = certToPem(certificate);
			try (FileOutputStream os = new FileOutputStream(f)) {
				os.write(pem.getBytes());
			}
		} catch (Exception ex) {
			Log.error("write cert to pem {} for host {} to fail", certificate, host);
		}
	}

	public static File getCertSaveFile(String host, String ext) {
		String file = String.format("certs/%s.%s", host, ext);
		File f = new File(file);
		return f;
	}

	public static X500Name getX500Name(String CN, String O, String L, String ST, String C, String OU) {
		X500NameBuilder rootIssueMessage = new X500NameBuilder(
				BCStrictStyle.INSTANCE);
		rootIssueMessage.addRDN(BCStyle.C, C);
		rootIssueMessage.addRDN(BCStyle.O, O);
//		rootIssueMessage.addRDN(BCStyle.L, L);
		rootIssueMessage.addRDN(BCStyle.ST, ST);
		rootIssueMessage.addRDN(BCStyle.OU, OU);
		rootIssueMessage.addRDN(BCStyle.CN, CN);
		return rootIssueMessage.build();
	}

    /**
     * 生成CA服务器证书
     */
    public static X509Certificate genCACert(String subject, Date caNotBefore, Date caNotAfter,
                                            KeyPair keyPair) throws Exception {
        JcaX509v3CertificateBuilder jv3Builder = new JcaX509v3CertificateBuilder(new X500Name(subject),
                BigInteger.valueOf(System.currentTimeMillis() + (long) (Math.random() * 10000) + 1000),
                caNotBefore,
                caNotAfter,
                new X500Name(subject),
                keyPair.getPublic());
        jv3Builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(jv3Builder.build(signer));
    }

  
    public static void main(String[] args) throws Exception {
        //生成ca证书和私钥
        KeyPair keyPair = CertUtil.genKeyPair();
        File caCertFile = new File("e:/ssl/Proxyee.crt");
        if (caCertFile.exists()) {
            caCertFile.delete();
        }
        Files.write(Paths.get(caCertFile.toURI()),
                CertUtil.genCACert(
                        "C=CN, ST=GD, L=SZ, O=lee, OU=study, CN=Proxyee",
                        new Date(),
                        new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(3650)),
                        keyPair)
                        .getEncoded());
    }
}
