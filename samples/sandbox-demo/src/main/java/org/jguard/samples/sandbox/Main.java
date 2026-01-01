/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.samples.sandbox;

import org.jguard.core.JGuard;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Demonstrates jGuard capability-based security enforcement.
 *
 * <p>This sample shows operations that require entitlements defined in
 * {@code module-info.jguard}:
 * <ul>
 *   <li>fs.read - filesystem read access to /tmp</li>
 *   <li>network.outbound - outbound network (in net package)</li>
 *   <li>threads.spawn - thread creation (in worker package)</li>
 * </ul>
 */
public final class Main {

    public static void main(String[] args) {
        System.out.println("jGuard Sandbox Demo");
        System.out.println("===================");
        System.out.println("Runtime version: " + JGuard.version());
        System.out.println();

        // Demonstrate filesystem access (entitled via module-level grant)
        demonstrateFilesystemAccess();

        // TODO: Once enforcement is implemented, these would be checked:
        // - org.jguard.samples.sandbox.net.* can make outbound connections
        // - org.jguard.samples.sandbox.worker.* can spawn threads
        // - Other packages would be denied these capabilities
    }

    /**
     * Demonstrates filesystem read access to /tmp.
     * This operation is entitled by: entitle module to fs.read("/tmp", ...)
     */
    private static void demonstrateFilesystemAccess() {
        System.out.println("[fs.read] Attempting to list /tmp directory...");

        Path tmpDir = Path.of("/tmp");
        try {
            long fileCount = Files.list(tmpDir).count();
            System.out.println("[fs.read] SUCCESS: Found " + fileCount + " entries in /tmp");
        } catch (IOException e) {
            System.out.println("[fs.read] FAILED: " + e.getMessage());
        }

        System.out.println();
    }
}
