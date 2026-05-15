/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.DenialCounters;
import io.jguard.bootstrap.Operation;

/** JMX MBean implementation that delegates to {@link DenialCounters}. */
public final class DenialCountersMBeanImpl implements DenialCountersMBean {

  @Override
  public long getTotalDenials() {
    return DenialCounters.totalCount();
  }

  @Override
  public long getFsReadDenials() {
    return DenialCounters.count(Operation.FS_READ);
  }

  @Override
  public long getFsWriteDenials() {
    return DenialCounters.count(Operation.FS_WRITE);
  }

  @Override
  public long getFsHardlinkDenials() {
    return DenialCounters.count(Operation.FS_HARDLINK);
  }

  @Override
  public long getNetConnectDenials() {
    return DenialCounters.count(Operation.NET_CONNECT);
  }

  @Override
  public long getNetListenDenials() {
    return DenialCounters.count(Operation.NET_LISTEN);
  }

  @Override
  public long getThreadCreateDenials() {
    return DenialCounters.count(Operation.THREAD_CREATE);
  }

  @Override
  public long getNativeLoadDenials() {
    return DenialCounters.count(Operation.NATIVE_LOAD);
  }

  @Override
  public long getEnvReadDenials() {
    return DenialCounters.count(Operation.ENV_READ);
  }

  @Override
  public long getPropReadDenials() {
    return DenialCounters.count(Operation.PROP_READ);
  }

  @Override
  public long getPropWriteDenials() {
    return DenialCounters.count(Operation.PROP_WRITE);
  }

  @Override
  public long getProcessExecDenials() {
    return DenialCounters.count(Operation.PROCESS_EXEC);
  }

  @Override
  public long getCryptoProviderDenials() {
    return DenialCounters.count(Operation.CRYPTO_PROVIDER);
  }

  @Override
  public long getRuntimeExitDenials() {
    return DenialCounters.count(Operation.RUNTIME_EXIT);
  }

  @Override
  public long getRuntimeShutdownHookDenials() {
    return DenialCounters.count(Operation.RUNTIME_SHUTDOWN_HOOK);
  }
}
