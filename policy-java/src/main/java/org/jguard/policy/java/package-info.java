/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * Java API for defining jGuard security policies.
 *
 * <p>This package provides a type-safe, fluent alternative to the {@code .jguard} policy DSL.
 * Policies defined in Java produce byte-identical output to equivalent {@code .jguard} files.
 *
 * <h2>Quick Start</h2>
 *
 * <pre>{@code
 * import static org.jguard.policy.java.Capabilities.*;
 * import static org.jguard.policy.java.Subjects.*;
 *
 * PolicyDescriptor policy = JGuardPolicy.forModule("com.example.app")
 *     .grant(module(), fsRead("/data", "*.json"))
 *     .grant(pkg("com.example.net"), networkOutbound())
 *     .grant(pkgRecursive("com.example.worker"), threadsSpawn())
 *     .build();
 * }</pre>
 *
 * <h2>Key Classes</h2>
 *
 * <ul>
 *   <li>{@link org.jguard.policy.java.JGuardPolicy} - Fluent builder for policies
 *   <li>{@link org.jguard.policy.java.Subjects} - Factory methods for subject patterns
 *   <li>{@link org.jguard.policy.java.Capabilities} - Factory methods for capabilities
 * </ul>
 *
 * <h2>When to Use</h2>
 *
 * <p>Use this API when you need:
 *
 * <ul>
 *   <li>Programmatic policy generation
 *   <li>IDE autocompletion and type safety
 *   <li>Integration with existing Java build tools
 *   <li>Dynamic policy construction based on runtime configuration
 * </ul>
 *
 * <p>For static policies, the {@code .jguard} DSL may be more readable.
 *
 * @see org.jguard.policy.java.JGuardPolicy
 */
package org.jguard.policy.java;
