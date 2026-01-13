/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * A simulated "overly permissive" third-party library.
 *
 * <p>This module has broad entitlements in its embedded policy:
 * - network.outbound to ANY host/port
 * - threads.create for the entire module
 * - native.load for the entire module
 *
 * <p>The external policy demo shows how to restrict these at deployment time
 * using deny statements.
 */
module io.jguard.samples.external.library {
  exports io.jguard.samples.external.library;
}
