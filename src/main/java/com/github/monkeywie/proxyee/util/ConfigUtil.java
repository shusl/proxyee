package com.github.monkeywie.proxyee.util;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Properties;

/**
 * Author: shushenglin
 * Date:   2018/12/7 22:04
 */
public class ConfigUtil {
	private static final Logger logger = LoggerFactory.getLogger(ConfigUtil.class);

	private static Properties properties;

	public static Properties getProperties() {
		return properties;
	}

	public static String getProperty(String key) {
		return properties.getProperty(key);
	}

	public static int getIntValue(String key, int defVal) {
		Integer val = getInteger(key);
		if (val == null) {
			return defVal;
		}
		return val;
	}

	public static Integer getInteger(String key) {
		String val = getProperty(key);
		if (val == null) {
			return null;
		}
		return Integer.parseInt(val);
	}

	public static void init(String configFile) {
		properties = loadFile(configFile);
	}


	public static Properties loadFile(String file) {
		Properties properties = new Properties();
		File f = new File(file);
		if (!f.exists()) {
			return properties;
		}
		try {
			properties.load(new FileInputStream(f));
		} catch (IOException e) {
			logger.error("load config {} error", file, e);
		}
		return properties;
	}

	public static void properties2Object(final Properties p, final String keyPrefix, final Object object) {
		Method[] methods = object.getClass().getMethods();
		for (Method method : methods) {
			String mn = method.getName();
			if (!mn.startsWith("set")) {
				continue;
			}
			String tmp = mn.substring(4);
			String first = mn.substring(3, 4);

			String key = first.toLowerCase() + tmp;
			if (StringUtils.isNotEmpty(keyPrefix)) {
				key = keyPrefix + key;
			}
			String property = p.getProperty(key);
			setProperty(object, method, property);
		}
	}

	public static void setProperty(Object object, Method method, String property) {
		if (property == null) {
			return;
		}
		try {
			Class<?>[] pt = method.getParameterTypes();
			if (pt != null && pt.length > 0) {
				String cn = pt[0].getSimpleName();
				Object arg = null;
				if (cn.equals("int") || cn.equals("Integer")) {
					arg = Integer.parseInt(property);
				} else if (cn.equals("long") || cn.equals("Long")) {
					arg = Long.parseLong(property);
				} else if (cn.equals("double") || cn.equals("Double")) {
					arg = Double.parseDouble(property);
				} else if (cn.equals("boolean") || cn.equals("Boolean")) {
					arg = Boolean.parseBoolean(property);
				} else if (cn.equals("float") || cn.equals("Float")) {
					arg = Float.parseFloat(property);
				} else if (cn.equals("String")) {
					arg = property;
				} else {
					return;
				}
				method.invoke(object, arg);
			}
		} catch (Throwable ignored) {
		}
	}
}
