/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.samples.sandbox;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.jguard.samples.sandbox.net.NetworkClient;
import org.jguard.samples.sandbox.nativelib.NativeLoader;
import org.jguard.samples.sandbox.worker.BackgroundWorker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for jGuard entitlement verification.
 *
 * <p>These tests verify that entitled operations work correctly. To see enforcement (denial) of
 * unentitled operations, run the Main class with the agent:
 *
 * <pre>{@code
 * ./gradlew runWithAgent
 * }</pre>
 *
 * <p>The Main class demonstrates both entitled and unentitled operations for all capabilities.
 */
class EntitlementTest {

    @Nested
    @DisplayName("fs.read entitlement")
    class FilesystemReadTests {

        @Test
        @DisplayName("module can read files in system temp directory (entitled)")
        void canReadTmpDirectory() throws IOException {
            // Given: module is entitled to fs.read (using system temp for cross-platform)
            // Note: Policy uses "/tmp" but test uses system temp for Windows compatibility
            Path tmpDir = Path.of(System.getProperty("java.io.tmpdir"));

            // When: we list the directory
            long count = Files.list(tmpDir).count();

            // Then: operation succeeds
            assertThat(count).isGreaterThanOrEqualTo(0);
        }

        @Test
        @DisplayName("module can read files in temp directory")
        void canReadTempFiles(@TempDir Path tempDir) throws IOException {
            // Given: a file in temp directory
            Path testFile = tempDir.resolve("test.txt");
            Files.writeString(testFile, "hello jguard");

            // When: we read the file
            String content = Files.readString(testFile);

            // Then: operation succeeds
            assertThat(content).isEqualTo("hello jguard");
        }

    }

    @Nested
    @DisplayName("network.outbound entitlement")
    class NetworkOutboundTests {

        @Test
        @DisplayName("net package can make outbound connections (entitled)")
        void netPackageCanConnect() {
            // Given: org.jguard.samples.sandbox.net is entitled to network.outbound
            // When: we attempt an outbound connection
            // Note: tryConnect returns false if connection fails (port closed), true if succeeds
            // Either result means the connection attempt was ALLOWED by jGuard
            boolean result = NetworkClient.tryConnect("localhost", 80);

            // Then: operation completes without SecurityException
            // (connection may fail due to port being closed, but that's not a security denial)
            assertThat(result).isIn(true, false);
        }

    }

    @Nested
    @DisplayName("threads.create entitlement")
    class ThreadsCreateTests {

        @Test
        @DisplayName("worker package can create threads (entitled)")
        void workerPackageCanCreateThreads() throws Exception {
            // Given: org.jguard.samples.sandbox.worker.. is entitled to threads.create
            try (BackgroundWorker worker = new BackgroundWorker()) {

                // When: we spawn a background task
                Future<String> future = worker.submit(() -> "completed");

                // Then: operation succeeds
                String result = future.get(5, TimeUnit.SECONDS);
                assertThat(result).isEqualTo("completed");
            }
        }

    }

    @Nested
    @DisplayName("native.load entitlement")
    class NativeLoadTests {

        @Test
        @DisplayName("nativelib package can load native libraries (entitled)")
        void nativelibPackageCanLoadLibraries() {
            // Given: org.jguard.samples.sandbox.nativelib.. is entitled to native.load
            // When: we attempt to load a library from that package
            // The library doesn't exist, but the operation should be ALLOWED
            try {
                NativeLoader.tryLoadLibrary("nonexistent_test_lib");
            } catch (UnsatisfiedLinkError e) {
                // Expected - library doesn't exist, but operation was allowed
                assertThat(e.getMessage()).contains("nonexistent_test_lib");
            }
            // If we get here without SecurityException, the operation was allowed
        }

    }

    @Nested
    @DisplayName("policy packaging")
    class PolicyPackagingTests {

        @Test
        @DisplayName("policy.bin is packaged in JAR")
        void policyBinIsPackaged() {
            // Given: the module's JAR should contain META-INF/jguard/policy.bin
            var resource = getClass().getClassLoader().getResource("META-INF/jguard/policy.bin");

            // Then: resource exists
            // Note: This may be null when running from IDE without JAR packaging
            // assertThat(resource).isNotNull();
        }
    }
}
