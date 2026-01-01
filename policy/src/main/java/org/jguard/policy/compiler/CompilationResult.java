/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.compiler;

import java.util.List;
import java.util.Objects;

/**
 * The result of compiling a jGuard policy descriptor.
 *
 * <p>A result is either successful or contains one or more diagnostic errors.
 * This is a value type - use {@link #success()} or {@link #failure(List)} to create instances.
 */
public final class CompilationResult {

    private final boolean success;
    private final List<Diagnostic> diagnostics;

    private CompilationResult(boolean success, List<Diagnostic> diagnostics) {
        this.success = success;
        this.diagnostics = List.copyOf(diagnostics);
    }

    /**
     * Creates a successful result with no diagnostics.
     */
    public static CompilationResult success() {
        return new CompilationResult(true, List.of());
    }

    /**
     * Creates a failed result with the given diagnostics.
     *
     * @param diagnostics the compilation errors (must not be empty)
     */
    public static CompilationResult failure(List<Diagnostic> diagnostics) {
        if (diagnostics.isEmpty()) {
            throw new IllegalArgumentException("Failure must have at least one diagnostic");
        }
        return new CompilationResult(false, diagnostics);
    }

    /**
     * Creates a failed result with a single diagnostic.
     */
    public static CompilationResult failure(Diagnostic diagnostic) {
        return failure(List.of(diagnostic));
    }

    public boolean isSuccess() {
        return success;
    }

    public boolean isFailure() {
        return !success;
    }

    /**
     * Returns the diagnostics. Empty if successful.
     */
    public List<Diagnostic> diagnostics() {
        return diagnostics;
    }

    /**
     * A diagnostic message from compilation, with optional source location.
     */
    public record Diagnostic(
        Severity severity,
        String message,
        String sourcePath,
        int line,
        int column
    ) {
        public Diagnostic {
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(message, "message");
        }

        /**
         * Creates an error diagnostic without location information.
         */
        public static Diagnostic error(String message) {
            return new Diagnostic(Severity.ERROR, message, null, -1, -1);
        }

        /**
         * Creates an error diagnostic with location.
         */
        public static Diagnostic error(String message, String sourcePath, int line, int column) {
            return new Diagnostic(Severity.ERROR, message, sourcePath, line, column);
        }

        public boolean hasLocation() {
            return line > 0;
        }

        @Override
        public String toString() {
            if (sourcePath == null || line < 0) {
                return severity + ": " + message;
            }
            if (column < 0) {
                return String.format("%s:%d: %s: %s", sourcePath, line, severity, message);
            }
            return String.format("%s:%d:%d: %s: %s", sourcePath, line, column, severity, message);
        }
    }

    public enum Severity {
        WARNING,
        ERROR
    }
}
