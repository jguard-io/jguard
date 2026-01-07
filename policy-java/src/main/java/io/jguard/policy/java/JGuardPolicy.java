/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.java;

import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.model.SubjectPattern;
import java.util.ArrayList;
import java.util.List;

/**
 * Fluent builder for creating jGuard policy descriptors in Java.
 *
 * <p>This class provides a type-safe, IDE-friendly alternative to the {@code .jguard} policy DSL.
 * Policies built with this API produce byte-identical output to equivalent {@code .jguard} files.
 *
 * <h2>Example Usage</h2>
 *
 * <pre>{@code
 * import static io.jguard.policy.java.Capabilities.*;
 * import static io.jguard.policy.java.Subjects.*;
 *
 * PolicyDescriptor policy = JGuardPolicy.forModule("com.example.app")
 *     .grant(module(), fsRead("/data", "*.json"))
 *     .grant(pkg("com.example.app.net"), networkOutbound())
 *     .grant(pkgRecursive("com.example.app.worker"), threadsCreate())
 *     .build();
 * }</pre>
 *
 * <h2>Parity with .jguard Files</h2>
 *
 * <p>The above Java code is equivalent to this {@code .jguard} file:
 *
 * <pre>{@code
 * security module com.example.app {
 *     entitle module to fs.read("/data", "*.json");
 *     entitle com.example.app.net to network.outbound;
 *     entitle com.example.app.worker.. to threads.create;
 * }
 * }</pre>
 *
 * <p>Both produce identical binary and JSON output when compiled.
 *
 * @see Capabilities
 * @see Subjects
 */
public final class JGuardPolicy {

  private final String moduleName;
  private final List<Entitlement> entitlements;

  private JGuardPolicy(String moduleName) {
    if (moduleName == null) {
      throw new IllegalArgumentException("Module name cannot be null");
    }
    if (moduleName.isEmpty()) {
      throw new IllegalArgumentException("Module name cannot be empty");
    }
    this.moduleName = moduleName;
    this.entitlements = new ArrayList<>();
  }

  /**
   * Creates a new policy builder for the specified module.
   *
   * @param moduleName the fully qualified module name (e.g., "com.example.app")
   * @return a new policy builder
   */
  public static JGuardPolicy forModule(String moduleName) {
    return new JGuardPolicy(moduleName);
  }

  /**
   * Grants a capability to a subject.
   *
   * @param subject the subject pattern (use {@link Subjects} factory methods)
   * @param capability the capability to grant (use {@link Capabilities} factory methods)
   * @return this builder for chaining
   */
  public JGuardPolicy grant(SubjectPattern subject, CapabilityGrant capability) {
    if (subject == null) {
      throw new IllegalArgumentException("Subject cannot be null");
    }
    if (capability == null) {
      throw new IllegalArgumentException("Capability cannot be null");
    }
    entitlements.add(new Entitlement(subject, capability));
    return this;
  }

  /**
   * Builds the policy descriptor.
   *
   * <p>The returned descriptor is immutable, sorted, and deduplicated. Identical policies built
   * from Java or parsed from {@code .jguard} files will produce byte-identical serialized output.
   *
   * @return the policy descriptor
   */
  public PolicyDescriptor build() {
    return PolicyDescriptor.create(moduleName, entitlements);
  }

  /**
   * Returns the module name for this policy.
   *
   * @return the module name
   */
  public String moduleName() {
    return moduleName;
  }

  /**
   * Returns the number of entitlements added so far.
   *
   * @return the entitlement count
   */
  public int entitlementCount() {
    return entitlements.size();
  }
}
