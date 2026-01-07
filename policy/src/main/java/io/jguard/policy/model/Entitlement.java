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
 * A single entitlement in a policy.
 *
 * <p>An entitlement grants a specific capability to a specific subject.
 *
 * @param subject the subject (who is granted the capability)
 * @param capability the capability being granted
 */
public record Entitlement(SubjectPattern subject, CapabilityGrant capability)
    implements Comparable<Entitlement> {

  private static final Comparator<Entitlement> COMPARATOR =
      Comparator.comparing(Entitlement::subject).thenComparing(Entitlement::capability);

  /** Compact constructor that validates the record fields. */
  public Entitlement {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(capability, "capability");
  }

  @Override
  public int compareTo(Entitlement other) {
    return COMPARATOR.compare(this, other);
  }
}
