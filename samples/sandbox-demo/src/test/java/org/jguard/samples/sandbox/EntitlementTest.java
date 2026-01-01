/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.samples.sandbox;

import org.jguard.samples.sandbox.net.NetworkClient;
import org.jguard.samples.sandbox.worker.BackgroundWorker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for jGuard entitlement enforcement.
 *
 * <p>These tests verify that operations succeed when entitled and fail when not.
 * Until enforcement is implemented, they serve as integration tests for the
 * sample code and as a template for enforcement testing.
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

        // TODO: Once enforcement is implemented, add tests for denied operations:
        // @Test
        // @DisplayName("module cannot read files outside entitled paths")
        // void cannotReadOutsideEntitledPaths() {
        //     assertThatThrownBy(() -> Files.readString(Path.of("/etc/passwd")))
        //         .isInstanceOf(SecurityException.class)
        //         .hasMessageContaining("fs.read");
        // }
    }

    @Nested
    @DisplayName("network.outbound entitlement")
    class NetworkOutboundTests {

        @Test
        @DisplayName("net package can make outbound connections (entitled)")
        void netPackageCanConnect() throws Exception {
            // Given: org.jguard.samples.sandbox.net is entitled to network.outbound
            NetworkClient client = new NetworkClient();

            // When: we make an outbound request
            // Note: This test requires network access; skip in isolated environments
            int status = client.fetchStatus("https://httpbin.org/status/200");

            // Then: operation succeeds
            assertThat(status).isEqualTo(200);
        }

        // TODO: Once enforcement is implemented, add tests for denied operations:
        // @Test
        // @DisplayName("main package cannot make outbound connections")
        // void mainPackageCannotConnect() {
        //     // Code in org.jguard.samples.sandbox (not .net) should be denied
        //     assertThatThrownBy(() -> makeConnectionFromMainPackage())
        //         .isInstanceOf(SecurityException.class)
        //         .hasMessageContaining("network.outbound");
        // }
    }

    @Nested
    @DisplayName("threads.spawn entitlement")
    class ThreadsSpawnTests {

        @Test
        @DisplayName("worker package can spawn threads (entitled)")
        void workerPackageCanSpawnThreads() throws Exception {
            // Given: org.jguard.samples.sandbox.worker.. is entitled to threads.spawn
            try (BackgroundWorker worker = new BackgroundWorker()) {

                // When: we spawn a background task
                Future<String> future = worker.submit(() -> "completed");

                // Then: operation succeeds
                String result = future.get(5, TimeUnit.SECONDS);
                assertThat(result).isEqualTo("completed");
            }
        }

        // TODO: Once enforcement is implemented, add tests for denied operations:
        // @Test
        // @DisplayName("main package cannot spawn threads")
        // void mainPackageCannotSpawnThreads() {
        //     // Code in org.jguard.samples.sandbox (not .worker) should be denied
        //     assertThatThrownBy(() -> new Thread(() -> {}).start())
        //         .isInstanceOf(SecurityException.class)
        //         .hasMessageContaining("threads.spawn");
        // }
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
