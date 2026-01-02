/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * Bootstrap classes for jGuard agent.
 *
 * <p>This package contains classes that are injected into the JVM's bootstrap classloader. These
 * classes are called by ByteBuddy advice woven into JDK classes like {@code java.nio.file.Files}.
 *
 * <h2>Design Constraints</h2>
 *
 * <p><b>IMPORTANT:</b> Classes in this package MUST NOT:
 *
 * <ul>
 *   <li>Have dependencies on external libraries (no SLF4J, ByteBuddy, etc.)
 *   <li>Reference classes outside this package and {@code java.*}
 *   <li>Perform complex initialization that could fail
 * </ul>
 *
 * <p>These constraints exist because:
 *
 * <ol>
 *   <li>Bootstrap classes can only see other bootstrap classes and JDK classes
 *   <li>Advice woven into JDK methods references bootstrap classes directly
 *   <li>Any {@code NoClassDefFoundError} will crash the JVM during class loading
 * </ol>
 *
 * <h2>Key Classes</h2>
 *
 * <ul>
 *   <li>{@link org.jguard.bootstrap.BootstrapEnforcer} - Main enforcement bridge
 *   <li>{@link org.jguard.bootstrap.AgentConfig} - Configuration from system properties
 *   <li>{@link org.jguard.bootstrap.EnforcementMode} - Enforcement mode (strict/permissive/audit)
 *   <li>{@link org.jguard.bootstrap.AgentLogger} - Simple console logger
 * </ul>
 */
package org.jguard.bootstrap;
