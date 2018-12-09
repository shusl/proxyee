package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.FullResponseIntercept;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import com.github.monkeywie.proxyee.util.ConfigUtil;
import com.github.monkeywie.proxyee.util.HttpUtil;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;

/**
 * Author: shushenglin
 * Date:   2018/12/7 21:10
 */
public class Bootstrap {

	private static final Logger logger = LoggerFactory.getLogger(Bootstrap.class);
	
	public static void main(String[] argv) {
		logger.info("start server");
		HttpProxyServerConfig config = new HttpProxyServerConfig();
		ConfigUtil.init("conf/server.conf");
		ConfigUtil.properties2Object(ConfigUtil.getProperties(),"server.", config);
		config.setHandleSsl(true);
		int serverPort = ConfigUtil.getIntValue("server.port", 9999);
		logger.info("server port {}", serverPort);
		new HttpProxyServer()
				.serverConfig(config)
				.proxyInterceptInitializer(new MyHttpProxyInterceptInitializer())
				.start(serverPort);
	}

	private static class MyHttpProxyInterceptInitializer extends HttpProxyInterceptInitializer {
		@Override
		public void init(HttpProxyInterceptPipeline pipeline) {
			pipeline.addLast(new FullResponseIntercept() {

				@Override
				public boolean match(HttpRequest httpRequest, HttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
					logger.info("receive request {} host: {}", httpRequest.uri(), httpRequest.headers().get(HttpHeaderNames.HOST));
					//在匹配到百度首页时插入js
					return StringUtils.equals(httpRequest.headers().get(HttpHeaderNames.HOST), "www.baidu.com");
				}

				@Override
				public void handelResponse(HttpRequest httpRequest, FullHttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
					//打印原始响应信息
					logger.info("receive response {}", httpResponse);
					logger.info("receive response content {}", httpResponse.content().toString(Charset.defaultCharset()));
					//修改响应头和响应体
					httpResponse.headers().set("handel", "edit head");
					httpResponse.content().writeBytes("<script>alert('hello proxyee')</script>".getBytes());
				}
			});
		}
	}
}
