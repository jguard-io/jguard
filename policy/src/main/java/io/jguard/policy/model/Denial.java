/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.model;

import java.util.Comparator;
import java.util.Objects;

/**
 * A single denial in a policy.
 *
 * <p>A denial removes a specific capability from a specific subject. Denials take precedence over
 * grants when merging policies.
 *
 * @param subject the subject (who is denied the capability)
 * @param capability the capability being denied
 * @param defensive if true, suppresses warnings when the denied capability was never granted
 */
public record Denial(SubjectPattern subject, CapabilityGrant capability, boolean defensive)
    implements Comparable<Denial> {

  private static final Comparator<Denial> COMPARATOR =
      Comparator.comparing(Denial::subject)
          .thenComparing(Denial::capability)
          .thenComparing(d -> d.defensive());

  /** Compact constructor that validates the record fields. */
  public Denial {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(capability, "capability");
  }

  /**
   * Creates a denial without the defensive modifier.
   *
   * @param subject the subject being denied
   * @param capability the capability being denied
   * @return the denial
   */
  public static Denial of(SubjectPattern subject, CapabilityGrant capability) {
    return new Denial(subject, capability, false);
  }

  /**
   * Creates a defensive denial (suppresses warning if capability not granted).
   *
   * @param subject the subject being denied
   * @param capability the capability being denied
   * @return the defensive denial
   */
  public static Denial defensive(SubjectPattern subject, CapabilityGrant capability) {
    return new Denial(subject, capability, true);
  }

  @Override
  public int compareTo(Denial other) {
    return COMPARATOR.compare(this, other);
  }
}
