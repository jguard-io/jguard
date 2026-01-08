/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * Network module providing HTTP client capabilities.
 *
 * <p>This module is entitled to make outbound network connections to specific hosts.
 */
module io.jguard.samples.multimodule.network {
  exports io.jguard.samples.multimodule.network;

  requires java.net.http;
}
