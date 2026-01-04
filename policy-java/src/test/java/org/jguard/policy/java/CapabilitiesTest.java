/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.java;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.jguard.policy.java.Capabilities.*;

import org.jguard.policy.model.CapabilityArgument;
import org.jguard.policy.model.CapabilityGrant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for {@link Capabilities}. */
class CapabilitiesTest {

  @Nested
  @DisplayName("fs.read")
  class FsReadTest {

    @Test
    @DisplayName("creates fs.read capability with arguments")
    void createsFsReadCapability() {
      CapabilityGrant capability = fsRead("/data", "*.json");

      assertThat(capability.name()).isEqualTo("fs.read");
      assertThat(capability.hasArguments()).isTrue();
      assertThat(capability.arguments()).hasSize(2);
    }

    @Test
    @DisplayName("fs.read arguments are strings")
    void argumentsAreStrings() {
      CapabilityGrant capability = fsRead("/data", "*.json");

      assertThat(capability.arguments().get(0)).isInstanceOf(CapabilityArgument.StringArg.class);
      assertThat(capability.arguments().get(1)).isInstanceOf(CapabilityArgument.StringArg.class);

      CapabilityArgument.StringArg root =
          (CapabilityArgument.StringArg) capability.arguments().get(0);
      CapabilityArgument.StringArg glob =
          (CapabilityArgument.StringArg) capability.arguments().get(1);

      assertThat(root.value()).isEqualTo("/data");
      assertThat(glob.value()).isEqualTo("*.json");
    }

    @Test
    @DisplayName("rejects null root")
    void rejectsNullRoot() {
      assertThatThrownBy(() -> fsRead(null, "*.json"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("root");
    }

    @Test
    @DisplayName("rejects null glob")
    void rejectsNullGlob() {
      assertThatThrownBy(() -> fsRead("/data", null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("glob");
    }
  }

  @Nested
  @DisplayName("fs.write")
  class FsWriteTest {

    @Test
    @DisplayName("creates fs.write capability with arguments")
    void createsFsWriteCapability() {
      CapabilityGrant capability = fsWrite("/tmp", "*.log");

      assertThat(capability.name()).isEqualTo("fs.write");
      assertThat(capability.arguments()).hasSize(2);
    }

    @Test
    @DisplayName("rejects null arguments")
    void rejectsNullArguments() {
      assertThatThrownBy(() -> fsWrite(null, "*.log")).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> fsWrite("/tmp", null)).isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Nested
  @DisplayName("network.outbound")
  class NetworkOutboundTest {

    @Test
    @DisplayName("creates network.outbound capability without arguments")
    void createsNetworkOutboundCapability() {
      CapabilityGrant capability = networkOutbound();

      assertThat(capability.name()).isEqualTo("network.outbound");
      assertThat(capability.hasArguments()).isFalse();
      assertThat(capability.arguments()).isEmpty();
    }
  }

  @Nested
  @DisplayName("network.listen")
  class NetworkListenTest {

    @Test
    @DisplayName("creates network.listen capability with port")
    void createsNetworkListenCapability() {
      CapabilityGrant capability = networkListen(8080);

      assertThat(capability.name()).isEqualTo("network.listen");
      assertThat(capability.hasArguments()).isTrue();
      assertThat(capability.arguments()).hasSize(1);
    }

    @Test
    @DisplayName("port argument is integer")
    void portArgumentIsInteger() {
      CapabilityGrant capability = networkListen(8080);

      assertThat(capability.arguments().get(0)).isInstanceOf(CapabilityArgument.IntegerArg.class);

      CapabilityArgument.IntegerArg port =
          (CapabilityArgument.IntegerArg) capability.arguments().get(0);
      assertThat(port.value()).isEqualTo(8080L);
    }

    @Test
    @DisplayName("accepts port 0")
    void acceptsPortZero() {
      CapabilityGrant capability = networkListen(0);

      CapabilityArgument.IntegerArg port =
          (CapabilityArgument.IntegerArg) capability.arguments().get(0);
      assertThat(port.value()).isEqualTo(0L);
    }

    @Test
    @DisplayName("accepts port 65535")
    void acceptsMaxPort() {
      CapabilityGrant capability = networkListen(65535);

      CapabilityArgument.IntegerArg port =
          (CapabilityArgument.IntegerArg) capability.arguments().get(0);
      assertThat(port.value()).isEqualTo(65535L);
    }

    @Test
    @DisplayName("rejects negative port")
    void rejectsNegativePort() {
      assertThatThrownBy(() -> networkListen(-1))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Port");
    }

    @Test
    @DisplayName("rejects port above 65535")
    void rejectsPortAboveMax() {
      assertThatThrownBy(() -> networkListen(65536))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Port");
    }
  }

  @Nested
  @DisplayName("threads.create")
  class ThreadsSpawnTest {

    @Test
    @DisplayName("creates threads.create capability without arguments")
    void createsThreadsSpawnCapability() {
      CapabilityGrant capability = threadsCreate();

      assertThat(capability.name()).isEqualTo("threads.create");
      assertThat(capability.hasArguments()).isFalse();
    }
  }

  @Nested
  @DisplayName("native.load")
  class NativeLoadTest {

    @Test
    @DisplayName("creates native.load capability without arguments")
    void createsNativeLoadCapability() {
      CapabilityGrant capability = nativeLoad();

      assertThat(capability.name()).isEqualTo("native.load");
      assertThat(capability.hasArguments()).isFalse();
    }
  }

  @Nested
  @DisplayName("Canonical String Output")
  class CanonicalStringTest {

    @Test
    @DisplayName("capabilities produce correct canonical strings")
    void correctCanonicalStrings() {
      assertThat(networkOutbound().toCanonicalString()).isEqualTo("network.outbound");
      assertThat(threadsCreate().toCanonicalString()).isEqualTo("threads.create");
      assertThat(nativeLoad().toCanonicalString()).isEqualTo("native.load");
      assertThat(networkListen(8080).toCanonicalString()).isEqualTo("network.listen(8080)");
      assertThat(fsRead("/data", "*.json").toCanonicalString())
          .isEqualTo("fs.read(\"/data\", \"*.json\")");
    }
  }
}
