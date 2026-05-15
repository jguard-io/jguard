/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

/**
 * JMX MBean interface for jGuard denial counters. Registered as {@code
 * io.jguard:type=DenialCounters}.
 */
public interface DenialCountersMBean {

  /** Returns total denial count across all operations. */
  long getTotalDenials();

  /** Returns denial count for fs.read operations. */
  long getFsReadDenials();

  /** Returns denial count for fs.write operations. */
  long getFsWriteDenials();

  /** Returns denial count for fs.hardlink operations. */
  long getFsHardlinkDenials();

  /** Returns denial count for network.outbound operations. */
  long getNetConnectDenials();

  /** Returns denial count for network.listen operations. */
  long getNetListenDenials();

  /** Returns denial count for threads.create operations. */
  long getThreadCreateDenials();

  /** Returns denial count for native.load operations. */
  long getNativeLoadDenials();

  /** Returns denial count for env.read operations. */
  long getEnvReadDenials();

  /** Returns denial count for system.property.read operations. */
  long getPropReadDenials();

  /** Returns denial count for system.property.write operations. */
  long getPropWriteDenials();

  /** Returns denial count for process.exec operations. */
  long getProcessExecDenials();

  /** Returns denial count for crypto.provider operations. */
  long getCryptoProviderDenials();

  /** Returns denial count for runtime.exit operations. */
  long getRuntimeExitDenials();

  /** Returns denial count for runtime.shutdown_hook operations. */
  long getRuntimeShutdownHookDenials();
}
