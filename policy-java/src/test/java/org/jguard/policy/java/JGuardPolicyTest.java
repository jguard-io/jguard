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
import static org.jguard.policy.java.Subjects.*;

import org.jguard.policy.model.PolicyDescriptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for {@link JGuardPolicy}. */
class JGuardPolicyTest {

  @Nested
  @DisplayName("Builder Creation")
  class BuilderCreationTest {

    @Test
    @DisplayName("creates builder with valid module name")
    void createsBuilderWithValidModuleName() {
      JGuardPolicy builder = JGuardPolicy.forModule("com.example.app");

      assertThat(builder.moduleName()).isEqualTo("com.example.app");
      assertThat(builder.entitlementCount()).isZero();
    }

    @Test
    @DisplayName("accepts simple module name")
    void acceptsSimpleModuleName() {
      JGuardPolicy builder = JGuardPolicy.forModule("app");

      assertThat(builder.moduleName()).isEqualTo("app");
    }

    @Test
    @DisplayName("rejects null module name")
    void rejectsNullModuleName() {
      assertThatThrownBy(() -> JGuardPolicy.forModule(null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("null");
    }

    @Test
    @DisplayName("rejects empty module name")
    void rejectsEmptyModuleName() {
      assertThatThrownBy(() -> JGuardPolicy.forModule(""))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("empty");
    }
  }

  @Nested
  @DisplayName("Grant Entitlements")
  class GrantEntitlementsTest {

    @Test
    @DisplayName("grants single entitlement")
    void grantsSingleEntitlement() {
      JGuardPolicy builder =
          JGuardPolicy.forModule("com.example.app").grant(module(), networkOutbound());

      assertThat(builder.entitlementCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("grants multiple entitlements")
    void grantsMultipleEntitlements() {
      JGuardPolicy builder =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), networkOutbound())
              .grant(pkg("com.example.net"), fsRead("/tmp", "*"))
              .grant(pkgRecursive("com.example.worker"), threadsCreate());

      assertThat(builder.entitlementCount()).isEqualTo(3);
    }

    @Test
    @DisplayName("returns same builder for chaining")
    void returnsSameBuilderForChaining() {
      JGuardPolicy builder = JGuardPolicy.forModule("com.example.app");
      JGuardPolicy returned = builder.grant(module(), networkOutbound());

      assertThat(returned).isSameAs(builder);
    }

    @Test
    @DisplayName("rejects null subject")
    void rejectsNullSubject() {
      JGuardPolicy builder = JGuardPolicy.forModule("com.example.app");

      assertThatThrownBy(() -> builder.grant(null, networkOutbound()))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Subject");
    }

    @Test
    @DisplayName("rejects null capability")
    void rejectsNullCapability() {
      JGuardPolicy builder = JGuardPolicy.forModule("com.example.app");

      assertThatThrownBy(() -> builder.grant(module(), null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Capability");
    }
  }

  @Nested
  @DisplayName("Build Policy")
  class BuildPolicyTest {

    @Test
    @DisplayName("builds empty policy")
    void buildsEmptyPolicy() {
      PolicyDescriptor policy = JGuardPolicy.forModule("com.example.app").build();

      assertThat(policy.moduleName()).isEqualTo("com.example.app");
      assertThat(policy.entitlements()).isEmpty();
    }

    @Test
    @DisplayName("builds policy with entitlements")
    void buildsPolicyWithEntitlements() {
      PolicyDescriptor policy =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), networkOutbound())
              .grant(pkg("com.example.net"), fsRead("/data", "*.json"))
              .build();

      assertThat(policy.moduleName()).isEqualTo("com.example.app");
      assertThat(policy.entitlements()).hasSize(2);
    }

    @Test
    @DisplayName("built policy has correct format version")
    void builtPolicyHasCorrectFormatVersion() {
      PolicyDescriptor policy = JGuardPolicy.forModule("com.example.app").build();

      assertThat(policy.formatVersion()).isEqualTo(1);
    }

    @Test
    @DisplayName("built policy is immutable")
    void builtPolicyIsImmutable() {
      PolicyDescriptor policy =
          JGuardPolicy.forModule("com.example.app").grant(module(), networkOutbound()).build();

      assertThatThrownBy(() -> policy.entitlements().clear())
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("can build multiple times")
    void canBuildMultipleTimes() {
      JGuardPolicy builder =
          JGuardPolicy.forModule("com.example.app").grant(module(), networkOutbound());

      PolicyDescriptor policy1 = builder.build();
      PolicyDescriptor policy2 = builder.build();

      assertThat(policy1.entitlements()).isEqualTo(policy2.entitlements());
    }
  }

  @Nested
  @DisplayName("Sorting and Deduplication")
  class SortingDeduplicationTest {

    @Test
    @DisplayName("entitlements are sorted by subject")
    void entitlementsAreSortedBySubject() {
      PolicyDescriptor policy =
          JGuardPolicy.forModule("com.example.app")
              .grant(pkg("z.pkg"), networkOutbound())
              .grant(module(), networkOutbound())
              .grant(pkg("a.pkg"), networkOutbound())
              .build();

      // MODULE should come first, then packages alphabetically
      assertThat(policy.entitlements().get(0).subject().packageName()).isNull(); // module
      assertThat(policy.entitlements().get(1).subject().packageName()).isEqualTo("a.pkg");
      assertThat(policy.entitlements().get(2).subject().packageName()).isEqualTo("z.pkg");
    }

    @Test
    @DisplayName("duplicate entitlements are deduplicated")
    void duplicateEntitlementsAreDeduplicated() {
      PolicyDescriptor policy =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), networkOutbound())
              .grant(module(), networkOutbound())
              .grant(module(), networkOutbound())
              .build();

      assertThat(policy.entitlements()).hasSize(1);
    }
  }
}
