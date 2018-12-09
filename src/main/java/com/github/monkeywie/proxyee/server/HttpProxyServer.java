package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.handler.HttpProxyServerHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class HttpProxyServer {
	private static final Logger logger = LoggerFactory.getLogger(HttpProxyServer.class);

	//http代理隧道握手成功
	public final static HttpResponseStatus SUCCESS = new HttpResponseStatus(200,
			"Connection established");
	public static final String INTERNAL_HTTPS_NAME = "internal-https";

	private HttpProxyCACertFactory caCertFactory;
	private HttpProxyServerConfig serverConfig;
	private HttpProxyInterceptInitializer proxyInterceptInitializer;
	private HttpProxyExceptionHandle httpProxyExceptionHandle;
	private ProxyConfig proxyConfig;


	private EventLoopGroup bossGroup;
	private EventLoopGroup workerGroup;

	private void init() {
		if (serverConfig == null) {
			serverConfig = new HttpProxyServerConfig();
		}
		serverConfig.setProxyLoopGroup(new NioEventLoopGroup(serverConfig.getProxyGroupThreads()));

		if (serverConfig.isHandleSsl()) {
			try {
				SslContextBuilder sslContextBuilder = SslContextBuilder.forClient();
				if (serverConfig.isDangerousIgnoreSSLError()) {
					sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
				}
				serverConfig.setClientSslCtx(
						sslContextBuilder
								.build());
				ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
				initCARootKey(classLoader);
				File pubFile = CertUtil.getCertSaveFile(INTERNAL_HTTPS_NAME, "pub");
				File priFile = CertUtil.getCertSaveFile(INTERNAL_HTTPS_NAME, "key");
				if (pubFile.exists() && priFile.exists()){
					logger.info("load private and public key from file {}, {}", priFile.getName(), pubFile.getName());
					PrivateKey priKey = CertUtil.generatePrivateKey(priFile.getAbsolutePath());
					PublicKey publicKey = CertUtil.generatePublicKey(pubFile.getAbsolutePath());
					serverConfig.setServerPubKey(publicKey);
					serverConfig.setServerPriKey(priKey);
				}else {
					//生产一对随机公私钥用于网站SSL证书动态创建
					KeyPair keyPair = CertUtil.genKeyPair();
					serverConfig.setServerPriKey(keyPair.getPrivate());
					serverConfig.setServerPubKey(keyPair.getPublic());
					CertUtil.savePrivateToDerFile(serverConfig.getServerPriKey(), INTERNAL_HTTPS_NAME);
					CertUtil.savePrivateToFile(serverConfig.getServerPriKey(), INTERNAL_HTTPS_NAME);
					CertUtil.savePublishToPemFile(serverConfig.getServerPubKey(), INTERNAL_HTTPS_NAME);
				}
			} catch (Exception e) {
				serverConfig.setHandleSsl(false);
				logger.error("init ssl fail ", e);
			}
		}
		if (proxyInterceptInitializer == null) {
			proxyInterceptInitializer = new HttpProxyInterceptInitializer();
		}
		if (httpProxyExceptionHandle == null) {
			httpProxyExceptionHandle = new HttpProxyExceptionHandle();
		}
	}

	private void initCARootKey(ClassLoader classLoader) throws Exception {
		X509Certificate caCert = null;
		PrivateKey caPriKey = null;
		if (caCertFactory == null) {
			String certFile = serverConfig.getCertFile();
			if (certFile != null && !certFile.isEmpty()) {
				File cf = new File(certFile);
				if (cf.exists()) {
					logger.info("load ca cert from {}", cf.getName());
					caCert = CertUtil.loadCert(cf.getAbsolutePath());
				}
			}
			if (caCert == null) {
				logger.info("load default ca cert");
				caCert = CertUtil.loadCert(classLoader.getResourceAsStream("ca.crt"));
			}
			String keyFile = serverConfig.getKeyFile();
			if (keyFile != null && !keyFile.isEmpty()) {
				File ck = new File(keyFile);
				if (ck.exists()) {
					logger.info("load ca private from {}", ck.getName());
					caPriKey = CertUtil.loadPriKey(ck.getAbsolutePath());
				}
			}
			if (caPriKey == null) {
				logger.info("load default ca private key");
				caPriKey = CertUtil.loadPriKey(classLoader.getResourceAsStream("ca_private.der"));
			}
		} else {
			logger.info("get cert from factory {}", caCertFactory);
			caCert = caCertFactory.getCACert();
			caPriKey = caCertFactory.getCAPriKey();
		}
		//读取CA证书使用者信息
		serverConfig.setIssuer(CertUtil.getSubject(caCert));
		serverConfig.setCaSubject(CertUtil.getCASubject(caCert));
		//读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
		serverConfig.setCaNotBefore(caCert.getNotBefore());
		serverConfig.setCaNotAfter(caCert.getNotAfter());
		serverConfig.setCaCert(caCert);
		//CA私钥用于给动态生成的网站SSL证书签证
		serverConfig.setCaPriKey(caPriKey);
		logger.info("cert info issuer {} expire {}-{} ", serverConfig.getIssuer(),
				serverConfig.getCaNotBefore(), serverConfig.getCaNotAfter());
	}

	public HttpProxyServer serverConfig(HttpProxyServerConfig serverConfig) {
		this.serverConfig = serverConfig;
		return this;
	}

	public HttpProxyServer proxyInterceptInitializer(
			HttpProxyInterceptInitializer proxyInterceptInitializer) {
		this.proxyInterceptInitializer = proxyInterceptInitializer;
		return this;
	}

	public HttpProxyServer httpProxyExceptionHandle(
			HttpProxyExceptionHandle httpProxyExceptionHandle) {
		this.httpProxyExceptionHandle = httpProxyExceptionHandle;
		return this;
	}

	public HttpProxyServer proxyConfig(ProxyConfig proxyConfig) {
		this.proxyConfig = proxyConfig;
		return this;
	}

	public HttpProxyServer caCertFactory(HttpProxyCACertFactory caCertFactory) {
		this.caCertFactory = caCertFactory;
		return this;
	}

	public void start(int port) {
		init();
		bossGroup = new NioEventLoopGroup(serverConfig.getBossGroupThreads());
		workerGroup = new NioEventLoopGroup(serverConfig.getWorkerGroupThreads());
		try {
			ServerBootstrap b = new ServerBootstrap();
			b.group(bossGroup, workerGroup)
					.channel(NioServerSocketChannel.class)
          .option(ChannelOption.SO_BACKLOG, 1024)
//					.handler(new LoggingHandler(LogLevel.DEBUG))
					.childHandler(new ChannelInitializer<Channel>() {

						@Override
						protected void initChannel(Channel ch) throws Exception {
							ch.pipeline().addLast("httpCodec", new HttpServerCodec());
							ch.pipeline().addLast("serverHandle",
									new HttpProxyServerHandle(serverConfig, proxyInterceptInitializer, proxyConfig,
											httpProxyExceptionHandle));
						}
					});
			ChannelFuture f = b
					.bind(port)
					.sync();
			f.channel().closeFuture().sync();
		} catch (Exception e) {
			logger.error("start server error port {}", port, e);
		} finally {
			bossGroup.shutdownGracefully();
			workerGroup.shutdownGracefully();
		}
	}

	public void close() {
		serverConfig.getProxyLoopGroup().shutdownGracefully();
		bossGroup.shutdownGracefully();
		workerGroup.shutdownGracefully();
		CertPool.clear();
	}

}
