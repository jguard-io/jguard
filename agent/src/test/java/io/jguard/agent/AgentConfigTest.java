/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.EnforcementMode;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Tests for {@link AgentConfig}. */
class AgentConfigTest {

  /** Creates a builder with discovery enabled (avoids policyPath requirement). */
  private static AgentConfig.Builder builder() {
    return new AgentConfig.Builder().discoveryEnabled(true);
  }

  @Nested
  @DisplayName("logAllowed()")
  class LogAllowedTests {

    @Test
    @DisplayName("defaults to false in STRICT mode")
    void defaultsFalseInStrictMode() {
      AgentConfig config = builder().mode(EnforcementMode.STRICT).build();
      assertThat(config.logAllowed()).isFalse();
    }

    @Test
    @DisplayName("defaults to true in AUDIT mode")
    void defaultsTrueInAuditMode() {
      AgentConfig config = builder().mode(EnforcementMode.AUDIT).build();
      assertThat(config.logAllowed()).isTrue();
    }

    @Test
    @DisplayName("defaults to false in PERMISSIVE mode")
    void defaultsFalseInPermissiveMode() {
      AgentConfig config = builder().mode(EnforcementMode.PERMISSIVE).build();
      assertThat(config.logAllowed()).isFalse();
    }

    @Test
    @DisplayName("explicit true overrides STRICT mode default")
    void explicitTrueOverridesStrictMode() {
      AgentConfig config = builder().mode(EnforcementMode.STRICT).logAllowed(true).build();
      assertThat(config.logAllowed()).isTrue();
    }

    @Test
    @DisplayName("explicit false overrides AUDIT mode default")
    void explicitFalseOverridesAuditMode() {
      AgentConfig config = builder().mode(EnforcementMode.AUDIT).logAllowed(false).build();
      assertThat(config.logAllowed()).isFalse();
    }

    @Test
    @DisplayName("explicit true in AUDIT mode keeps true")
    void explicitTrueInAuditModeKeepsTrue() {
      AgentConfig config = builder().mode(EnforcementMode.AUDIT).logAllowed(true).build();
      assertThat(config.logAllowed()).isTrue();
    }

    @Test
    @DisplayName("explicit false in STRICT mode keeps false")
    void explicitFalseInStrictModeKeepsFalse() {
      AgentConfig config = builder().mode(EnforcementMode.STRICT).logAllowed(false).build();
      assertThat(config.logAllowed()).isFalse();
    }
  }

  @Nested
  @DisplayName("logDenied()")
  class LogDeniedTests {

    @Test
    @DisplayName("defaults to true")
    void defaultsTrue() {
      AgentConfig config = builder().build();
      assertThat(config.logDenied()).isTrue();
    }

    @Test
    @DisplayName("can be set to false")
    void canBeSetToFalse() {
      AgentConfig config = builder().logDenied(false).build();
      assertThat(config.logDenied()).isFalse();
    }
  }

  @Nested
  @DisplayName("overrideDirs()")
  class OverrideDirsTests {

    @Test
    @DisplayName("defaults to empty list")
    void defaultsToEmptyList() {
      AgentConfig config = builder().build();
      assertThat(config.overrideDirs()).isEmpty();
    }

    @Test
    @DisplayName("single directory via overrideDir()")
    void singleDirectoryViaOverrideDir() {
      AgentConfig config = builder().overrideDir(Path.of("/etc/policies")).build();
      assertThat(config.overrideDirs()).containsExactly(Path.of("/etc/policies"));
    }

    @Test
    @DisplayName("multiple directories via addOverrideDir()")
    void multipleDirectoriesViaAddOverrideDir() {
      AgentConfig config =
          builder()
              .addOverrideDir(Path.of("/etc/policies"))
              .addOverrideDir(Path.of("/app/test-policies"))
              .build();
      assertThat(config.overrideDirs())
          .containsExactly(Path.of("/etc/policies"), Path.of("/app/test-policies"));
    }

    @Test
    @DisplayName("overrideDir() clears previously added directories")
    void overrideDirClearsPreviouslyAdded() {
      AgentConfig config =
          builder()
              .addOverrideDir(Path.of("/first"))
              .addOverrideDir(Path.of("/second"))
              .overrideDir(Path.of("/only"))
              .build();
      assertThat(config.overrideDirs()).containsExactly(Path.of("/only"));
    }

    @Test
    @DisplayName("overrideDir(null) clears all directories")
    void overrideDirNullClearsAll() {
      AgentConfig config =
          builder()
              .addOverrideDir(Path.of("/first"))
              .addOverrideDir(Path.of("/second"))
              .overrideDir(null)
              .build();
      assertThat(config.overrideDirs()).isEmpty();
    }

    @Test
    @DisplayName("list is immutable")
    void listIsImmutable() {
      AgentConfig config = builder().addOverrideDir(Path.of("/etc/policies")).build();
      assertThat(config.overrideDirs()).isUnmodifiable();
    }
  }
}
