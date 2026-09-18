/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.bootstrap.BootstrapEnforcer;
import io.jguard.bootstrap.EnforcementMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Logging must be changeable on a running JVM.
 *
 * <p>It was not: {@code jguard.log.allowed} and {@code jguard.log.denied} were read once at startup
 * and written into the bootstrap enforcer, so changing either meant restarting the process -- and
 * on a clustered application, restarting every node. That is an absurd price for a log level, and
 * it is paid at exactly the wrong moment, since the reason to want allowed-operation logging is
 * that something is wrong right now.
 */
class ControlMBeanTest {

  private final ControlMBean control = new ControlMBeanImpl();

  @AfterEach
  void restoreDefaults() {
    BootstrapEnforcer.setLogging(true, false);
  }

  @Test
  @DisplayName("allowed-operation logging can be turned on and off at runtime")
  void logAllowedRoundTrips() {
    BootstrapEnforcer.setLogging(true, false);
    assertThat(control.getLogAllowed()).isFalse();

    control.setLogAllowed(true);
    assertThat(control.getLogAllowed())
        .as("the firehose could not be turned on without a restart, which is the whole point")
        .isTrue();

    control.setLogAllowed(false);
    assertThat(control.getLogAllowed())
        .as(
            "and it must be possible to turn it off again -- it is a line per intercepted operation")
        .isFalse();
  }

  @Test
  @DisplayName("setting one logging flag does not disturb the other")
  void flagsAreIndependent() {
    // setLogging writes both flags at once, so an implementation that passes a literal for the
    // one it is not changing silently resets it. Turning the firehose on would then switch
    // denial logging OFF, which is the one thing that must never stop being reported.
    BootstrapEnforcer.setLogging(true, false);

    control.setLogAllowed(true);
    assertThat(control.getLogDenied())
        .as("turning allowed-logging on must not silently disable denial logging")
        .isTrue();

    control.setLogDenied(false);
    assertThat(control.getLogAllowed())
        .as("changing denial logging must not disturb the allowed-logging setting")
        .isTrue();
  }

  @Test
  @DisplayName("reports the enforcement mode actually in force")
  void reportsMode() {
    EnforcementMode original = BootstrapEnforcer.mode();
    try {
      BootstrapEnforcer.setMode(EnforcementMode.PERMISSIVE);
      assertThat(control.getMode()).isEqualTo("PERMISSIVE");
    } finally {
      BootstrapEnforcer.setMode(original);
    }
  }

  @Test
  @DisplayName("mode is read-only over JMX")
  void modeIsNotWritable() {
    // Enforcement posture must not be editable from a management port. Policy arrives through
    // signed policy files; logging is not a security control and this interface is scoped to it.
    assertThat(ControlMBean.class.getMethods())
        .as("no setter for the enforcement mode may exist on the control interface")
        .noneMatch(m -> m.getName().equals("setMode"));
  }
}
