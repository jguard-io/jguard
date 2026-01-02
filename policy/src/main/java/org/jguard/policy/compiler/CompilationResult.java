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
 * <p>A result is either successful or contains one or more diagnostic errors. This is a value type
 * - use {@link #success()} or {@link #failure(List)} to create instances.
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
   *
   * @return the successful result
   */
  public static CompilationResult success() {
    return new CompilationResult(true, List.of());
  }

  /**
   * Creates a failed result with the given diagnostics.
   *
   * @param diagnostics the compilation errors (must not be empty)
   * @return the failed result
   */
  public static CompilationResult failure(List<Diagnostic> diagnostics) {
    if (diagnostics.isEmpty()) {
      throw new IllegalArgumentException("Failure must have at least one diagnostic");
    }
    return new CompilationResult(false, diagnostics);
  }

  /**
   * Creates a failed result with a single diagnostic.
   *
   * @param diagnostic the compilation error
   * @return the failed result
   */
  public static CompilationResult failure(Diagnostic diagnostic) {
    return failure(List.of(diagnostic));
  }

  /**
   * Returns true if compilation succeeded.
   *
   * @return true if successful
   */
  public boolean isSuccess() {
    return success;
  }

  /**
   * Returns true if compilation failed.
   *
   * @return true if failed
   */
  public boolean isFailure() {
    return !success;
  }

  /**
   * Returns the diagnostics. Empty if successful.
   *
   * @return the list of diagnostics
   */
  public List<Diagnostic> diagnostics() {
    return diagnostics;
  }

  /**
   * A diagnostic message from compilation, with optional source location.
   *
   * @param severity the diagnostic severity
   * @param message the diagnostic message
   * @param sourcePath the source file path (may be null)
   * @param line the 1-based line number (-1 if unknown)
   * @param column the 1-based column number (-1 if unknown)
   */
  public record Diagnostic(
      Severity severity, String message, String sourcePath, int line, int column) {
    /** Compact constructor that validates the required fields. */
    public Diagnostic {
      Objects.requireNonNull(severity, "severity");
      Objects.requireNonNull(message, "message");
    }

    /**
     * Creates an error diagnostic without location information.
     *
     * @param message the error message
     * @return the error diagnostic
     */
    public static Diagnostic error(String message) {
      return new Diagnostic(Severity.ERROR, message, null, -1, -1);
    }

    /**
     * Creates an error diagnostic with location.
     *
     * @param message the error message
     * @param sourcePath the source file path
     * @param line the 1-based line number
     * @param column the 1-based column number
     * @return the error diagnostic
     */
    public static Diagnostic error(String message, String sourcePath, int line, int column) {
      return new Diagnostic(Severity.ERROR, message, sourcePath, line, column);
    }

    /**
     * Returns true if this diagnostic has source location information.
     *
     * @return true if location is available
     */
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

  /** Severity levels for compilation diagnostics. */
  public enum Severity {
    /** A warning that does not prevent compilation from succeeding. */
    WARNING,

    /** An error that prevents compilation from succeeding. */
    ERROR
  }
}
