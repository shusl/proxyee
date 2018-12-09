package com.github.monkeywie.proxyee.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Author: shushenglin
 * Date:   2017/3/9 16:58
 */
public class Log {
	private static final Logger infoLogger = LoggerFactory.getLogger("info");
	private static final Logger debugLogger = LoggerFactory.getLogger("debug");
	private static final Logger warnLogger = LoggerFactory.getLogger("warn");
	private static final Logger errorLogger = LoggerFactory.getLogger("error");
	private static final Logger ignoreLogger = LoggerFactory.getLogger("ignore");

	public static void debug(String msg) {
		debugLogger.debug(msg);
	}

	public static void debug(String format, Object arg) {
		debugLogger.debug(format, arg);
	}

	public static void debug(String format, Object arg1, Object arg2) {
		debugLogger.debug(format, arg1, arg2);
	}

	public static void debug(String format, Object... arguments) {
		debugLogger.debug(format, arguments);
	}

	public static void debug(String msg, Throwable t) {
		debugLogger.debug(msg, t);
	}

	public static void info(String msg) {
		infoLogger.info(msg);
	}

	public static void info(String format, Object arg) {
		infoLogger.info(format, arg);
	}

	public static void info(String format, Object arg1, Object arg2) {
		infoLogger.info(format, arg1, arg2);
	}

	public static void info(String format, Object... arguments) {
		infoLogger.info(format, arguments);
	}

	public static void warn(String msg) {
		warnLogger.warn(msg);
	}

	public static void warn(String format, Object arg) {
		warnLogger.warn(format, arg);
	}

	public static void warn(String format, Object... arguments) {
		warnLogger.warn(format, arguments);
	}

	public static void warn(String format, Object arg1, Object arg2) {
		warnLogger.warn(format, arg1, arg2);
	}

	public static void warn(String msg, Throwable t) {
		warnLogger.warn(msg, t);
	}

	public static void error(String msg) {
		errorLogger.error(msg);
	}

	public static void error(String format, Object arg) {
		errorLogger.error(format, arg);
	}

	public static void error(String format, Object arg1, Object arg2) {
		errorLogger.error(format, arg1, arg2);
	}

	public static void error(String format, Object... arguments) {
		errorLogger.error(format, arguments);
	}

	public static void error(String msg, Throwable t) {
		errorLogger.error(msg, t);
	}

	public static void ignorable(String msg){
		ignoreLogger.error(msg);
	}

	public static void ignorable(String msg, Throwable t){
		ignoreLogger.error(msg, t);
	}

	public static void ignorable(String msg, Object... arguments) {
		ignoreLogger.error(msg, arguments);
	}

	public static boolean isDebugEnabled() {
		return debugLogger.isDebugEnabled();
	}

	public static Logger getInfoLogger() {
		return infoLogger;
	}

	public static Logger getDebugLogger() {
		return debugLogger;
	}

	public static Logger getWarnLogger() {
		return warnLogger;
	}

	public static Logger getErrorLogger() {
		return errorLogger;
	}

	public static Logger getIgnoreLogger() {
		return ignoreLogger;
	}
}
