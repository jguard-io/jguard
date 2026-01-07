/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for policy model classes. */
class ModelTest {

  @Nested
  class SubjectPatternTest {

    @Test
    void createsModuleSubject() {
      SubjectPattern subject = SubjectPattern.module();

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.MODULE);
      assertThat(subject.packageName()).isNull();
    }

    @Test
    void createsExactPackageSubject() {
      SubjectPattern subject = SubjectPattern.exactPackage("com.example");

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.PACKAGE_EXACT);
      assertThat(subject.packageName()).isEqualTo("com.example");
    }

    @Test
    void createsDirectChildrenSubject() {
      SubjectPattern subject = SubjectPattern.directChildren("com.example");

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.PACKAGE_DIRECT_CHILDREN);
      assertThat(subject.packageName()).isEqualTo("com.example");
    }

    @Test
    void createsRecursiveSubject() {
      SubjectPattern subject = SubjectPattern.recursive("com.example");

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.PACKAGE_RECURSIVE);
      assertThat(subject.packageName()).isEqualTo("com.example");
    }

    @Test
    void toCanonicalStringForModule() {
      SubjectPattern subject = SubjectPattern.module();
      assertThat(subject.toCanonicalString()).isEqualTo("module");
    }

    @Test
    void toCanonicalStringForExactPackage() {
      SubjectPattern subject = SubjectPattern.exactPackage("com.example");
      assertThat(subject.toCanonicalString()).isEqualTo("com.example");
    }

    @Test
    void toCanonicalStringForDirectChildren() {
      SubjectPattern subject = SubjectPattern.directChildren("com.example");
      assertThat(subject.toCanonicalString()).isEqualTo("com.example.*");
    }

    @Test
    void toCanonicalStringForRecursive() {
      SubjectPattern subject = SubjectPattern.recursive("com.example");
      assertThat(subject.toCanonicalString()).isEqualTo("com.example..");
    }

    @Test
    void toStringMatchesToCanonicalString() {
      SubjectPattern subject = SubjectPattern.recursive("com.example");
      assertThat(subject.toString()).isEqualTo(subject.toCanonicalString());
    }

    @Test
    void compareToOrdersByTypeThenPackageName() {
      SubjectPattern module = SubjectPattern.module();
      SubjectPattern pkgA = SubjectPattern.exactPackage("a.b");
      SubjectPattern pkgB = SubjectPattern.exactPackage("b.c");
      SubjectPattern directA = SubjectPattern.directChildren("a.b");
      SubjectPattern recursiveA = SubjectPattern.recursive("a.b");

      // MODULE comes first (enum ordinal)
      assertThat(module.compareTo(pkgA)).isLessThan(0);

      // Same type, compare by package name
      assertThat(pkgA.compareTo(pkgB)).isLessThan(0);

      // Different types with same package
      assertThat(pkgA.compareTo(directA)).isLessThan(0);
      assertThat(directA.compareTo(recursiveA)).isLessThan(0);
    }

    @Test
    void rejectsModuleWithPackageName() {
      assertThatThrownBy(() -> new SubjectPattern(SubjectPattern.Type.MODULE, "com.example"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("null packageName");
    }

    @Test
    void rejectsPackageTypeWithNullPackageName() {
      assertThatThrownBy(() -> new SubjectPattern(SubjectPattern.Type.PACKAGE_EXACT, null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("packageName");
    }

    @Test
    void rejectsPackageTypeWithEmptyPackageName() {
      assertThatThrownBy(() -> new SubjectPattern(SubjectPattern.Type.PACKAGE_EXACT, ""))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("packageName");
    }
  }

  @Nested
  class CapabilityArgumentTest {

    @Test
    void createsStringArgument() {
      CapabilityArgument.StringArg arg = new CapabilityArgument.StringArg("/data");

      assertThat(arg.value()).isEqualTo("/data");
    }

    @Test
    void createsIntegerArgument() {
      CapabilityArgument.IntegerArg arg = new CapabilityArgument.IntegerArg(8080);

      assertThat(arg.value()).isEqualTo(8080L);
    }

    @Test
    void stringArgToCanonicalString() {
      CapabilityArgument.StringArg arg = new CapabilityArgument.StringArg("/data");
      assertThat(arg.toCanonicalString()).isEqualTo("\"/data\"");
    }

    @Test
    void integerArgToCanonicalString() {
      CapabilityArgument.IntegerArg arg = new CapabilityArgument.IntegerArg(8080);
      assertThat(arg.toCanonicalString()).isEqualTo("8080");
    }

    @Test
    void stringArgRejectsNull() {
      assertThatThrownBy(() -> new CapabilityArgument.StringArg(null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("null");
    }
  }

  @Nested
  class CapabilityGrantTest {

    @Test
    void createsCapabilityWithoutArguments() {
      CapabilityGrant capability = CapabilityGrant.of("network.outbound");

      assertThat(capability.name()).isEqualTo("network.outbound");
      assertThat(capability.hasArguments()).isFalse();
      assertThat(capability.arguments()).isEmpty();
    }

    @Test
    void createsCapabilityWithArguments() {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.StringArg("*.json")));

      assertThat(capability.name()).isEqualTo("fs.read");
      assertThat(capability.hasArguments()).isTrue();
      assertThat(capability.arguments()).hasSize(2);
    }

    @Test
    void toCanonicalStringWithoutArguments() {
      CapabilityGrant capability = CapabilityGrant.of("network.outbound");
      assertThat(capability.toCanonicalString()).isEqualTo("network.outbound");
    }

    @Test
    void toCanonicalStringWithArguments() {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.IntegerArg(123)));

      assertThat(capability.toCanonicalString()).isEqualTo("fs.read(\"/data\", 123)");
    }

    @Test
    void compareToOrdersByNameThenArguments() {
      CapabilityGrant fsRead = CapabilityGrant.of("fs.read");
      CapabilityGrant networkOut = CapabilityGrant.of("network.outbound");

      assertThat(fsRead.compareTo(networkOut)).isLessThan(0);
    }

    @Test
    void createsDefensiveCopyOfArguments() {
      List<CapabilityArgument> args =
          new java.util.ArrayList<>(List.of(new CapabilityArgument.StringArg("/data")));
      CapabilityGrant capability = CapabilityGrant.of("fs.read", args);

      args.add(new CapabilityArgument.IntegerArg(123));

      assertThat(capability.arguments()).hasSize(1);
    }

    @Test
    void argumentsAreImmutable() {
      CapabilityGrant capability =
          CapabilityGrant.of("fs.read", List.of(new CapabilityArgument.StringArg("/data")));

      assertThatThrownBy(() -> capability.arguments().add(new CapabilityArgument.IntegerArg(123)))
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsNullName() {
      assertThatThrownBy(() -> new CapabilityGrant(null, List.of()))
          .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsEmptyName() {
      assertThatThrownBy(() -> new CapabilityGrant("", List.of()))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Nested
  class EntitlementTest {

    @Test
    void createsEntitlement() {
      SubjectPattern subject = SubjectPattern.module();
      CapabilityGrant capability = CapabilityGrant.of("network.outbound");
      Entitlement entitlement = new Entitlement(subject, capability);

      assertThat(entitlement.subject()).isEqualTo(subject);
      assertThat(entitlement.capability()).isEqualTo(capability);
    }

    @Test
    void compareToOrdersBySubjectThenCapability() {
      Entitlement moduleNet =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement moduleFs =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("fs.read"));
      Entitlement pkgNet =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("network.outbound"));

      // Same subject, compare by capability name
      assertThat(moduleFs.compareTo(moduleNet)).isLessThan(0);

      // Different subjects
      assertThat(moduleNet.compareTo(pkgNet)).isLessThan(0);
    }

    @Test
    void rejectsNullSubject() {
      assertThatThrownBy(() -> new Entitlement(null, CapabilityGrant.of("network.outbound")))
          .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsNullCapability() {
      assertThatThrownBy(() -> new Entitlement(SubjectPattern.module(), null))
          .isInstanceOf(NullPointerException.class);
    }
  }

  @Nested
  class PolicyDescriptorTest {

    @Test
    void createsPolicyDescriptor() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      assertThat(policy.formatVersion()).isEqualTo(1);
      assertThat(policy.moduleName()).isEqualTo("com.example.app");
      assertThat(policy.entitlements()).isEmpty();
    }

    @Test
    void createsPolicyDescriptorWithEntitlements() {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));

      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(e1));

      assertThat(policy.entitlements()).hasSize(1);
    }

    @Test
    void sortsEntitlements() {
      Entitlement e1 =
          new Entitlement(
              SubjectPattern.exactPackage("z.pkg"), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e3 =
          new Entitlement(
              SubjectPattern.exactPackage("a.pkg"), CapabilityGrant.of("network.outbound"));

      // Pass in unsorted order
      PolicyDescriptor policy = PolicyDescriptor.create("com.example", List.of(e1, e2, e3));

      // Should be sorted: module first, then package names alphabetically
      assertThat(policy.entitlements().get(0).subject()).isEqualTo(SubjectPattern.module());
      assertThat(policy.entitlements().get(1).subject().packageName()).isEqualTo("a.pkg");
      assertThat(policy.entitlements().get(2).subject().packageName()).isEqualTo("z.pkg");
    }

    @Test
    void deduplicatesEntitlements() {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));

      PolicyDescriptor policy = PolicyDescriptor.create("com.example", List.of(e1, e2));

      assertThat(policy.entitlements()).hasSize(1);
    }

    @Test
    void entitlementsAreImmutable() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example", List.of());

      assertThatThrownBy(
              () ->
                  policy
                      .entitlements()
                      .add(
                          new Entitlement(
                              SubjectPattern.module(), CapabilityGrant.of("network.outbound"))))
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsNullModuleName() {
      assertThatThrownBy(() -> PolicyDescriptor.create(null, List.of()))
          .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsEmptyModuleName() {
      assertThatThrownBy(() -> PolicyDescriptor.create("", List.of()))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("empty");
    }

    @Test
    void formatVersionIsOne() {
      assertThat(PolicyDescriptor.FORMAT_VERSION).isEqualTo(1);
    }
  }
}
