package com.github.monkeywie.proxyee.crt;

import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import com.github.monkeywie.proxyee.util.Log;

import java.io.File;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

public class CertPool {

    private static Map<Integer, Map<String, X509Certificate>> certCache = new WeakHashMap<>();

  
    public static X509Certificate getCert(Integer port, String host, HttpProxyServerConfig serverConfig)
            throws Exception {
        X509Certificate cert = null;
        if (host != null) {
            Map<String, X509Certificate> portCertCache = certCache.get(port);
            if (portCertCache == null) {
                portCertCache = new HashMap<>();
                certCache.put(port, portCertCache);
            }
            String key = host.trim().toLowerCase();
            if (portCertCache.containsKey(key)) {
                return portCertCache.get(key);
            } else {
				File certFile = CertUtil.getCertSaveFile(host, "crt");
				if (certFile.exists()) {
					Log.info("load cert from file {}", certFile.getName());
					try {
						cert = CertUtil.loadCert(certFile.getAbsolutePath());
					} catch (Exception ex) {
						Log.error("load cert from file {} fail", certFile.getName(), ex);
					}
				}
				if (cert == null) {
					HttpProxyServerConfig sc = serverConfig;
					cert = CertUtil.genCert(sc.getCaSubject(), sc.getCaPriKey(), sc.getServerPubKey(),
							sc.getCaNotBefore(), sc.getCaNotAfter(), key);
					CertUtil.saveToFile(cert, host);
				}
                portCertCache.put(key, cert);
            }
        }
        return cert;
    }

  
    public static void clear() {
        certCache.clear();
    }
}
