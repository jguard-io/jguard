/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * Main application module.
 *
 * <p>This module has minimal entitlements - it delegates sensitive operations to the core and
 * network modules which have their own specific entitlements.
 */
module io.jguard.samples.multimodule.app {
  requires io.jguard.samples.multimodule.core;
  requires io.jguard.samples.multimodule.network;
}
