/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.worker;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Background worker entitled to create threads.
 *
 * <p>This class is in the {@code io.jguard.samples.sandbox.worker} package,
 * which is entitled to {@code threads.create} capability (including subpackages).
 */
public final class BackgroundWorker implements AutoCloseable {

    private final ExecutorService executor;

    public BackgroundWorker() {
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
    }

    /**
     * Submits a task to run in the background.
     *
     * @param task the task to execute
     * @param <T> the result type
     * @return a Future representing the pending result
     */
    public <T> Future<T> submit(Callable<T> task) {
        return executor.submit(task);
    }

    /**
     * Submits a runnable to run in the background.
     *
     * @param task the task to execute
     * @return a Future representing the pending completion
     */
    public Future<?> submit(Runnable task) {
        return executor.submit(task);
    }

    @Override
    public void close() {
        executor.shutdown();
    }
}
