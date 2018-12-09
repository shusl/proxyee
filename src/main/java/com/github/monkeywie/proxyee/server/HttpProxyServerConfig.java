package com.github.monkeywie.proxyee.server;

import io.netty.channel.EventLoopGroup;
import io.netty.handler.ssl.SslContext;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class HttpProxyServerConfig {
	private SslContext clientSslCtx;
	private String issuer;
	private Date caNotBefore;
	private Date caNotAfter;
	private PrivateKey caPriKey;
	private PrivateKey serverPriKey;
	private PublicKey serverPubKey;
	private EventLoopGroup proxyLoopGroup;
	private int bossGroupThreads = 1;
	private int workerGroupThreads = 16;
	private int proxyGroupThreads = 16;
	private boolean handleSsl;
	private String certFile;
	private String keyFile;
	private boolean dangerousIgnoreSSLError = false;
	private X509Certificate caCert;
	private X500Name caSubject;

	public boolean isDangerousIgnoreSSLError() {
		return dangerousIgnoreSSLError;
	}

	public HttpProxyServerConfig setDangerousIgnoreSSLError(boolean dangerousIgnoreSSLError) {
		this.dangerousIgnoreSSLError = dangerousIgnoreSSLError;
		return this;
	}

	public String getCertFile() {
		return certFile;
	}

	public HttpProxyServerConfig setCertFile(String certFile) {
		this.certFile = certFile;
		return this;
	}

	public String getKeyFile() {
		return keyFile;
	}

	public HttpProxyServerConfig setKeyFile(String keyFile) {
		this.keyFile = keyFile;
		return this;
	}

	public SslContext getClientSslCtx() {
		return clientSslCtx;
	}

	public void setClientSslCtx(SslContext clientSslCtx) {
		this.clientSslCtx = clientSslCtx;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public Date getCaNotBefore() {
		return caNotBefore;
	}

	public void setCaNotBefore(Date caNotBefore) {
		this.caNotBefore = caNotBefore;
	}

	public Date getCaNotAfter() {
		return caNotAfter;
	}

	public void setCaNotAfter(Date caNotAfter) {
		this.caNotAfter = caNotAfter;
	}

	public PrivateKey getCaPriKey() {
		return caPriKey;
	}

	public void setCaPriKey(PrivateKey caPriKey) {
		this.caPriKey = caPriKey;
	}

	public PrivateKey getServerPriKey() {
		return serverPriKey;
	}

	public void setServerPriKey(PrivateKey serverPriKey) {
		this.serverPriKey = serverPriKey;
	}

	public PublicKey getServerPubKey() {
		return serverPubKey;
	}

	public void setServerPubKey(PublicKey serverPubKey) {
		this.serverPubKey = serverPubKey;
	}

	public EventLoopGroup getProxyLoopGroup() {
		return proxyLoopGroup;
	}

	public void setProxyLoopGroup(EventLoopGroup proxyLoopGroup) {
		this.proxyLoopGroup = proxyLoopGroup;
	}

	public boolean isHandleSsl() {
		return handleSsl;
	}

	public void setHandleSsl(boolean handleSsl) {
		this.handleSsl = handleSsl;
	}

	public int getBossGroupThreads() {
		return bossGroupThreads;
	}

	public void setBossGroupThreads(int bossGroupThreads) {
		this.bossGroupThreads = bossGroupThreads;
	}

	public int getWorkerGroupThreads() {
		return workerGroupThreads;
	}

	public void setWorkerGroupThreads(int workerGroupThreads) {
		this.workerGroupThreads = workerGroupThreads;
	}

	public int getProxyGroupThreads() {
		return proxyGroupThreads;
	}

	public void setProxyGroupThreads(int proxyGroupThreads) {
		this.proxyGroupThreads = proxyGroupThreads;
	}

	public void setCaCert(X509Certificate caCert) {
		this.caCert = caCert;
	}

	public X509Certificate getCaCert() {
		return caCert;
	}

	public void setCaSubject(X500Name caSubject) {
		this.caSubject = caSubject;
	}

	public X500Name getCaSubject() {
		return caSubject;
	}
}
