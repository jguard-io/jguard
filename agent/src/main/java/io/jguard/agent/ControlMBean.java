/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

/**
 * JMX MBean for changing jGuard's logging on a running JVM. Registered as {@code
 * io.jguard:type=Control}.
 *
 * <p>Logging was previously fixed for the life of the process: {@code jguard.log.allowed} and
 * {@code jguard.log.denied} were read once at startup and written straight into the bootstrap
 * enforcer. Turning either on or off meant a restart, which on a clustered application means a
 * rolling restart of every node -- an expensive way to change a log level, and one nobody performs
 * while actually debugging.
 *
 * <p>Allowed-operation logging is the reason this exists. It is a line for every property read,
 * file open and socket connect the application makes, so it is genuinely useful for a minute and
 * ruinous for an hour. Being able to switch it on, read it, and switch it off again is the
 * difference between a usable diagnostic and one that gets left on.
 *
 * <p>Enforcement is deliberately not exposed here. The mode decides whether denials throw, and
 * changing that on a live JVM through a management interface would make the security posture of a
 * running process editable from outside it. Policy is reloaded through the policy files, which are
 * signed; logging is not a security control.
 */
public interface ControlMBean {

  /**
   * Returns whether denied operations are currently logged.
   *
   * @return true if denials are logged
   */
  boolean getLogDenied();

  /**
   * Sets whether denied operations are logged.
   *
   * <p>Defaults to true and should normally stay there: a denial is the event the agent exists to
   * report.
   *
   * @param value true to log denials
   */
  void setLogDenied(boolean value);

  /**
   * Returns whether allowed operations are currently logged.
   *
   * @return true if allowed operations are logged
   */
  boolean getLogAllowed();

  /**
   * Sets whether allowed operations are logged.
   *
   * <p>Off by default in every mode. This is the firehose -- one line per intercepted operation, at
   * INFO -- so turn it on to answer a question and turn it off again afterwards.
   *
   * @param value true to log allowed operations
   */
  void setLogAllowed(boolean value);

  /**
   * Returns the current enforcement mode as a string.
   *
   * <p>Read-only on purpose: see the class documentation.
   *
   * @return STRICT, PERMISSIVE or AUDIT
   */
  String getMode();
}
