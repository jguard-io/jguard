/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.BootstrapEnforcer;

/**
 * JMX control implementation that reads and writes the bootstrap enforcer's logging flags directly.
 *
 * <p>Deliberately not backed by {@code AgentConfig}. The config records what the JVM was started
 * with; the enforcer holds what is actually in force. Once either can be changed at runtime those
 * two stop agreeing, and the one worth reporting -- and the only one worth writing to -- is the
 * enforcer.
 */
public final class ControlMBeanImpl implements ControlMBean {

  @Override
  public boolean getLogDenied() {
    return BootstrapEnforcer.logDenied();
  }

  @Override
  public void setLogDenied(boolean value) {
    // setLogging writes both flags, so the other one has to be carried through unchanged --
    // otherwise turning one on silently resets the other to whatever this call happened to pass.
    BootstrapEnforcer.setLogging(value, BootstrapEnforcer.logAllowed());
  }

  @Override
  public boolean getLogAllowed() {
    return BootstrapEnforcer.logAllowed();
  }

  @Override
  public void setLogAllowed(boolean value) {
    BootstrapEnforcer.setLogging(BootstrapEnforcer.logDenied(), value);
  }

  @Override
  public String getMode() {
    return BootstrapEnforcer.mode().name();
  }
}
