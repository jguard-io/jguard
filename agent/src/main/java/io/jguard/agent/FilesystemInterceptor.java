/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.BootstrapEnforcer;
import java.io.File;
import java.nio.file.Path;
import net.bytebuddy.asm.Advice;

/**
 * ByteBuddy advice for intercepting filesystem read operations.
 *
 * <p>This class contains static advice methods that are woven into JDK filesystem classes to
 * enforce fs.read entitlements.
 *
 * <p><b>Important:</b> All advice methods MUST only reference classes from the {@code
 * io.jguard.bootstrap} package and JDK classes. The bootstrap package is injected into the
 * bootstrap classloader, making it visible to transformed JDK classes. Any reference to
 * non-bootstrap classes will cause {@link NoClassDefFoundError} at runtime.
 */
public final class FilesystemInterceptor {

  private FilesystemInterceptor() {
    // Advice class
  }

  /**
   * Advice for methods that take a Path parameter.
   *
   * <p>Applied to: Files.readString, Files.readAllBytes, Files.list, Files.walk, FileChannel.open,
   * etc.
   */
  public static class PathAdvice {

    private PathAdvice() {}

    /**
     * Intercepts method entry to enforce fs.read policy.
     *
     * @param path the path being accessed
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) Path path) {
      // ONLY reference BootstrapEnforcer - it's injected into bootstrap classloader
      BootstrapEnforcer.onFileRead(path);
    }
  }

  /**
   * Advice for constructors/methods that take a File parameter.
   *
   * <p>Applied to: FileInputStream(File), RandomAccessFile(File, String), FileReader(File)
   */
  public static class FileAdvice {

    private FileAdvice() {}

    /**
     * Intercepts method entry to enforce fs.read policy.
     *
     * @param file the file being accessed
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) File file) {
      // ONLY reference BootstrapEnforcer - it's injected into bootstrap classloader
      BootstrapEnforcer.onFileRead(file);
    }
  }

  /**
   * Advice for constructors/methods that take a String path parameter.
   *
   * <p>Applied to: FileInputStream(String), RandomAccessFile(String, String), FileReader(String)
   */
  public static class StringPathAdvice {

    private StringPathAdvice() {}

    /**
     * Intercepts method entry to enforce fs.read policy.
     *
     * @param path the path string being accessed
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String path) {
      // ONLY reference BootstrapEnforcer - it's injected into bootstrap classloader
      BootstrapEnforcer.onFileRead(path);
    }
  }

  // ========== WRITE ADVICE CLASSES ==========

  /**
   * Advice for write methods that take a Path parameter.
   *
   * <p>Applied to: Files.write, Files.writeString, Files.newOutputStream, Files.newBufferedWriter,
   * Files.copy (destination), Files.move (destination), etc.
   */
  public static class WritePathAdvice {

    private WritePathAdvice() {}

    /**
     * Intercepts method entry to enforce fs.write policy.
     *
     * @param path the path being written
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) Path path) {
      // ONLY reference BootstrapEnforcer - it's injected into bootstrap classloader
      BootstrapEnforcer.onFileWrite(path);
    }
  }

  /**
   * Advice for write constructors/methods that take a File parameter.
   *
   * <p>Applied to: FileOutputStream(File), FileWriter(File)
   */
  public static class WriteFileAdvice {

    private WriteFileAdvice() {}

    /**
     * Intercepts method entry to enforce fs.write policy.
     *
     * @param file the file being written
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) File file) {
      // ONLY reference BootstrapEnforcer - it's injected into bootstrap classloader
      BootstrapEnforcer.onFileWrite(file);
    }
  }

  /**
   * Advice for write constructors/methods that take a String path parameter.
   *
   * <p>Applied to: FileOutputStream(String), FileWriter(String)
   */
  public static class WriteStringPathAdvice {

    private WriteStringPathAdvice() {}

    /**
     * Intercepts method entry to enforce fs.write policy.
     *
     * @param path the path string being written
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String path) {
      // ONLY reference BootstrapEnforcer - it's injected into bootstrap classloader
      BootstrapEnforcer.onFileWrite(path);
    }
  }
}
