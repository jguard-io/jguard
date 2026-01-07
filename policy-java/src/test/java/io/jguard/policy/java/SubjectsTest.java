/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.java;

import static io.jguard.policy.java.Subjects.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jguard.policy.model.SubjectPattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for {@link Subjects}. */
class SubjectsTest {

  @Nested
  @DisplayName("module()")
  class ModuleSubjectTest {

    @Test
    @DisplayName("creates module subject")
    void createsModuleSubject() {
      SubjectPattern subject = module();

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.MODULE);
      assertThat(subject.packageName()).isNull();
    }

    @Test
    @DisplayName("module subject canonical string is 'module'")
    void canonicalStringIsModule() {
      SubjectPattern subject = module();

      assertThat(subject.toCanonicalString()).isEqualTo("module");
    }
  }

  @Nested
  @DisplayName("pkg()")
  class ExactPackageSubjectTest {

    @Test
    @DisplayName("creates exact package subject")
    void createsExactPackageSubject() {
      SubjectPattern subject = pkg("com.example.net");

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.PACKAGE_EXACT);
      assertThat(subject.packageName()).isEqualTo("com.example.net");
    }

    @Test
    @DisplayName("accepts simple package name")
    void acceptsSimplePackageName() {
      SubjectPattern subject = pkg("net");

      assertThat(subject.packageName()).isEqualTo("net");
    }

    @Test
    @DisplayName("canonical string is package name")
    void canonicalStringIsPackageName() {
      SubjectPattern subject = pkg("com.example.net");

      assertThat(subject.toCanonicalString()).isEqualTo("com.example.net");
    }

    @Test
    @DisplayName("rejects null package name")
    void rejectsNullPackageName() {
      assertThatThrownBy(() -> pkg(null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("null");
    }

    @Test
    @DisplayName("rejects empty package name")
    void rejectsEmptyPackageName() {
      assertThatThrownBy(() -> pkg(""))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("empty");
    }

    @Test
    @DisplayName("rejects package name starting with dot")
    void rejectsLeadingDot() {
      assertThatThrownBy(() -> pkg(".com.example"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid");
    }

    @Test
    @DisplayName("rejects package name ending with dot")
    void rejectsTrailingDot() {
      assertThatThrownBy(() -> pkg("com.example."))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid");
    }
  }

  @Nested
  @DisplayName("pkgChildren()")
  class DirectChildrenSubjectTest {

    @Test
    @DisplayName("creates direct children subject")
    void createsDirectChildrenSubject() {
      SubjectPattern subject = pkgChildren("com.example.handlers");

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.PACKAGE_DIRECT_CHILDREN);
      assertThat(subject.packageName()).isEqualTo("com.example.handlers");
    }

    @Test
    @DisplayName("canonical string includes .*")
    void canonicalStringIncludesStar() {
      SubjectPattern subject = pkgChildren("com.example.handlers");

      assertThat(subject.toCanonicalString()).isEqualTo("com.example.handlers.*");
    }

    @Test
    @DisplayName("rejects null package name")
    void rejectsNullPackageName() {
      assertThatThrownBy(() -> pkgChildren(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects empty package name")
    void rejectsEmptyPackageName() {
      assertThatThrownBy(() -> pkgChildren("")).isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Nested
  @DisplayName("pkgRecursive()")
  class RecursiveSubjectTest {

    @Test
    @DisplayName("creates recursive subject")
    void createsRecursiveSubject() {
      SubjectPattern subject = pkgRecursive("com.example.worker");

      assertThat(subject.type()).isEqualTo(SubjectPattern.Type.PACKAGE_RECURSIVE);
      assertThat(subject.packageName()).isEqualTo("com.example.worker");
    }

    @Test
    @DisplayName("canonical string includes ..")
    void canonicalStringIncludesDoubleDot() {
      SubjectPattern subject = pkgRecursive("com.example.worker");

      assertThat(subject.toCanonicalString()).isEqualTo("com.example.worker..");
    }

    @Test
    @DisplayName("rejects null package name")
    void rejectsNullPackageName() {
      assertThatThrownBy(() -> pkgRecursive(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects empty package name")
    void rejectsEmptyPackageName() {
      assertThatThrownBy(() -> pkgRecursive("")).isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Nested
  @DisplayName("Subject Comparison")
  class SubjectComparisonTest {

    @Test
    @DisplayName("module comes before packages")
    void moduleComesFirst() {
      SubjectPattern module = module();
      SubjectPattern pkg = pkg("com.example");

      assertThat(module.compareTo(pkg)).isLessThan(0);
    }

    @Test
    @DisplayName("packages are ordered alphabetically")
    void packagesOrderedAlphabetically() {
      SubjectPattern a = pkg("a.pkg");
      SubjectPattern z = pkg("z.pkg");

      assertThat(a.compareTo(z)).isLessThan(0);
    }

    @Test
    @DisplayName("same package different types are ordered by type")
    void samePackageDifferentTypes() {
      SubjectPattern exact = pkg("com.example");
      SubjectPattern children = pkgChildren("com.example");
      SubjectPattern recursive = pkgRecursive("com.example");

      assertThat(exact.compareTo(children)).isLessThan(0);
      assertThat(children.compareTo(recursive)).isLessThan(0);
    }
  }

  @Nested
  @DisplayName("Subject Equality")
  class SubjectEqualityTest {

    @Test
    @DisplayName("equal subjects are equal")
    void equalSubjectsAreEqual() {
      assertThat(module()).isEqualTo(module());
      assertThat(pkg("com.example")).isEqualTo(pkg("com.example"));
      assertThat(pkgChildren("com.example")).isEqualTo(pkgChildren("com.example"));
      assertThat(pkgRecursive("com.example")).isEqualTo(pkgRecursive("com.example"));
    }

    @Test
    @DisplayName("different subjects are not equal")
    void differentSubjectsAreNotEqual() {
      assertThat(module()).isNotEqualTo(pkg("com.example"));
      assertThat(pkg("com.example")).isNotEqualTo(pkgChildren("com.example"));
      assertThat(pkg("a.pkg")).isNotEqualTo(pkg("b.pkg"));
    }
  }
}
