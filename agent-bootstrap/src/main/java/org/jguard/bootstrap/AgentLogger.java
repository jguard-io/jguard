/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.bootstrap;

import java.io.PrintStream;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Simple console logger for jGuard agent internals.
 *
 * <p>This logger is designed for use in bootstrap-loaded classes where SLF4J and other logging
 * frameworks are not available. It writes directly to System.err to avoid any classloading
 * dependencies.
 *
 * <p>Log levels are controlled via the {@code jguard.log.level} system property.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * private static final AgentLogger LOG = AgentLogger.getLogger(MyClass.class);
 * LOG.info("Message with {} args", arg1);
 * }</pre>
 */
public final class AgentLogger {

  /** Log levels in order of verbosity. */
  public enum Level {
    /** Error level - critical issues that may cause failures. */
    ERROR(0),
    /** Warning level - issues that should be addressed but don't prevent operation. */
    WARN(1),
    /** Info level - informational messages about normal operation. */
    INFO(2),
    /** Debug level - detailed information for debugging. */
    DEBUG(3),
    /** Trace level - very detailed information for tracing execution. */
    TRACE(4);

    private final int value;

    Level(int value) {
      this.value = value;
    }

    boolean isEnabled(Level threshold) {
      return this.value <= threshold.value;
    }
  }

  private static final DateTimeFormatter FORMATTER =
      DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

  private static volatile Level globalLevel = Level.INFO;
  private static volatile boolean initialized = false;

  private final String name;

  private AgentLogger(String name) {
    this.name = name;
  }

  /**
   * Gets a logger for the specified class.
   *
   * @param clazz the class to create a logger for
   * @return a new logger instance
   */
  public static AgentLogger getLogger(Class<?> clazz) {
    ensureInitialized();
    return new AgentLogger(clazz.getSimpleName());
  }

  /**
   * Gets a logger with the specified name.
   *
   * @param name the logger name
   * @return a new logger instance
   */
  public static AgentLogger getLogger(String name) {
    ensureInitialized();
    return new AgentLogger(name);
  }

  /**
   * Sets the global log level.
   *
   * @param level the log level to set
   */
  public static void setLevel(Level level) {
    globalLevel = level;
  }

  /**
   * Gets the current global log level.
   *
   * @return the current log level
   */
  public static Level getLevel() {
    return globalLevel;
  }

  private static void ensureInitialized() {
    if (!initialized) {
      synchronized (AgentLogger.class) {
        if (!initialized) {
          String levelProp = System.getProperty("jguard.log.level", "info");
          try {
            globalLevel = Level.valueOf(levelProp.toUpperCase());
          } catch (IllegalArgumentException e) {
            // Default to INFO if invalid
            globalLevel = Level.INFO;
          }
          initialized = true;
        }
      }
    }
  }

  /**
   * Logs an error message.
   *
   * @param message the message to log
   */
  public void error(String message) {
    log(Level.ERROR, message);
  }

  /**
   * Logs a formatted error message.
   *
   * @param format the format string with {} placeholders
   * @param args the arguments to substitute
   */
  public void error(String format, Object... args) {
    log(Level.ERROR, format, args);
  }

  /**
   * Logs an error message with a throwable.
   *
   * @param message the message to log
   * @param t the throwable to log
   */
  public void error(String message, Throwable t) {
    log(Level.ERROR, message, t);
  }

  /**
   * Logs a warning message.
   *
   * @param message the message to log
   */
  public void warn(String message) {
    log(Level.WARN, message);
  }

  /**
   * Logs a formatted warning message.
   *
   * @param format the format string with {} placeholders
   * @param args the arguments to substitute
   */
  public void warn(String format, Object... args) {
    log(Level.WARN, format, args);
  }

  /**
   * Logs a warning message with a throwable.
   *
   * @param message the message to log
   * @param t the throwable to log
   */
  public void warn(String message, Throwable t) {
    log(Level.WARN, message, t);
  }

  /**
   * Logs an info message.
   *
   * @param message the message to log
   */
  public void info(String message) {
    log(Level.INFO, message);
  }

  /**
   * Logs a formatted info message.
   *
   * @param format the format string with {} placeholders
   * @param args the arguments to substitute
   */
  public void info(String format, Object... args) {
    log(Level.INFO, format, args);
  }

  /**
   * Logs a debug message.
   *
   * @param message the message to log
   */
  public void debug(String message) {
    log(Level.DEBUG, message);
  }

  /**
   * Logs a formatted debug message.
   *
   * @param format the format string with {} placeholders
   * @param args the arguments to substitute
   */
  public void debug(String format, Object... args) {
    log(Level.DEBUG, format, args);
  }

  /**
   * Logs a trace message.
   *
   * @param message the message to log
   */
  public void trace(String message) {
    log(Level.TRACE, message);
  }

  /**
   * Logs a formatted trace message.
   *
   * @param format the format string with {} placeholders
   * @param args the arguments to substitute
   */
  public void trace(String format, Object... args) {
    log(Level.TRACE, format, args);
  }

  /**
   * Returns true if debug level is enabled.
   *
   * @return true if debug logging is enabled
   */
  public boolean isDebugEnabled() {
    return Level.DEBUG.isEnabled(globalLevel);
  }

  /**
   * Returns true if trace level is enabled.
   *
   * @return true if trace logging is enabled
   */
  public boolean isTraceEnabled() {
    return Level.TRACE.isEnabled(globalLevel);
  }

  private void log(Level level, String message) {
    if (!level.isEnabled(globalLevel)) {
      return;
    }
    PrintStream out = System.err;
    out.printf(
        "%s [%s] [jguard] %s - %s%n", FORMATTER.format(Instant.now()), level.name(), name, message);
  }

  private void log(Level level, String format, Object... args) {
    if (!level.isEnabled(globalLevel)) {
      return;
    }
    String message = formatMessage(format, args);
    log(level, message);
  }

  private void log(Level level, String message, Throwable t) {
    if (!level.isEnabled(globalLevel)) {
      return;
    }
    log(level, message);
    t.printStackTrace(System.err);
  }

  /**
   * Formats a message with SLF4J-style {} placeholders.
   *
   * @param format the format string with {} placeholders
   * @param args the arguments to substitute
   * @return the formatted message
   */
  private static String formatMessage(String format, Object... args) {
    if (args == null || args.length == 0) {
      return format;
    }

    StringBuilder sb = new StringBuilder(format.length() + 50);
    int argIndex = 0;
    int i = 0;

    while (i < format.length()) {
      if (i < format.length() - 1 && format.charAt(i) == '{' && format.charAt(i + 1) == '}') {
        if (argIndex < args.length) {
          sb.append(args[argIndex++]);
        } else {
          sb.append("{}");
        }
        i += 2;
      } else {
        sb.append(format.charAt(i));
        i++;
      }
    }

    return sb.toString();
  }
}
