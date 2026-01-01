/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.compiler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Compiles jGuard policy descriptors ({@code module-info.jguard}) into
 * binary and optional JSON formats.
 *
 * <p>This is the main entry point for policy compilation, used by both
 * the Gradle plugin and CLI.
 */
public final class PolicyCompiler {

    private PolicyCompiler() {
        // Static utility class
    }

    /**
     * Compiles a policy descriptor file into binary format and optionally JSON.
     *
     * @param source the path to the {@code module-info.jguard} source file
     * @param binOutput the path where the binary policy file will be written
     * @param jsonOutput the path where the JSON policy file will be written, or {@code null} to skip JSON
     * @return the compilation result indicating success or failure with diagnostics
     * @throws IOException if an I/O error occurs during compilation
     */
    public static CompilationResult compile(Path source, Path binOutput, Path jsonOutput) throws IOException {
        if (!Files.exists(source)) {
            return CompilationResult.failure(
                CompilationResult.Diagnostic.error("Source file does not exist: " + source)
            );
        }

        // Ensure output directories exist
        Files.createDirectories(binOutput.getParent());

        // TODO: Implement actual compilation
        // 1. Parse the source file using the policy grammar
        // 2. Build the PolicyDescriptor AST
        // 3. Validate well-formedness rules
        // 4. Serialize to binary format
        // 5. Optionally serialize to JSON

        // Placeholder: write stub outputs for now
        Files.writeString(binOutput, "JGUARD_POLICY_V1\n");

        if (jsonOutput != null) {
            Files.createDirectories(jsonOutput.getParent());
            Files.writeString(jsonOutput, "{\"version\": 1, \"placeholder\": true}\n");
        }

        return CompilationResult.success();
    }
}
