/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.bootstrap;

/**
 * Callback interface for policy enforcement.
 *
 * <p>This interface is the bridge between the bootstrap-loaded enforcement layer and the agent's
 * policy evaluation. It is injected into the bootstrap classloader along with other bootstrap
 * types, allowing the agent to implement it directly without reflection or proxy overhead.
 *
 * <h2>Thread Safety</h2>
 *
 * <p>Implementations must be thread-safe as they may be called concurrently from multiple threads.
 *
 * <h2>Error Handling</h2>
 *
 * <p>Implementations should return a {@link SecurityException} for denied operations rather than
 * throwing, to allow the bootstrap layer to apply enforcement mode semantics.
 */
@FunctionalInterface
public interface EnforcementCallback {

  /**
   * Checks if an operation should be allowed.
   *
   * @param caller the caller context (package and module information)
   * @param op the operation being performed
   * @param arg0 primary argument (type depends on operation - see {@link Operation} for contracts)
   * @param arg1 secondary argument (type depends on operation - see {@link Operation} for
   *     contracts)
   * @return null if the operation is allowed, or a {@link SecurityException} if denied
   */
  SecurityException check(CallerContext caller, Operation op, Object arg0, int arg1);
}
