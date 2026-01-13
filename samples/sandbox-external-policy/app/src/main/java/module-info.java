/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * Application demonstrating external policy grant/deny.
 *
 * <p>This application uses a "third-party" library that has overly permissive
 * embedded policies. The external policy files in the {@code policies/} directory
 * demonstrate how to restrict those permissions at deployment time.
 */
module io.jguard.samples.external.app {
  requires io.jguard.samples.external.library;
}
