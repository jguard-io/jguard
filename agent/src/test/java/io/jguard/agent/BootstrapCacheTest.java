/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.Version;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for the bootstrap JAR caching logic in JGuardAgent.
 *
 * <p>These tests verify:
 *
 * <ul>
 *   <li>Cache directory path selection for different platforms
 *   <li>Cache file naming based on version
 *   <li>JAR file validation
 *   <li>Security validation (symlinks, ownership, permissions)
 *   <li>Secure permission setting
 * </ul>
 */
class BootstrapCacheTest {

  @TempDir Path tempDir;

  // ========== Cache Directory Tests ==========

  @Test
  void getUserCacheDir_withSystemPropertyOverride_returnsOverridePath() {
    String originalValue = System.getProperty(JGuardAgent.CACHE_DIR_PROPERTY);
    try {
      System.setProperty(JGuardAgent.CACHE_DIR_PROPERTY, "/custom/cache/path");
      Path cacheDir = JGuardAgent.getUserCacheDir();
      assertThat(cacheDir).isEqualTo(Path.of("/custom/cache/path"));
    } finally {
      if (originalValue != null) {
        System.setProperty(JGuardAgent.CACHE_DIR_PROPERTY, originalValue);
      } else {
        System.clearProperty(JGuardAgent.CACHE_DIR_PROPERTY);
      }
    }
  }

  @Test
  void getUserCacheDir_withEmptySystemProperty_usesDefault() {
    String originalValue = System.getProperty(JGuardAgent.CACHE_DIR_PROPERTY);
    try {
      System.setProperty(JGuardAgent.CACHE_DIR_PROPERTY, "");
      Path cacheDir = JGuardAgent.getUserCacheDir();
      // Should fall back to default (not empty path)
      assertThat(cacheDir.toString()).isNotEmpty();
      assertThat(cacheDir.toString()).contains("jguard");
    } finally {
      if (originalValue != null) {
        System.setProperty(JGuardAgent.CACHE_DIR_PROPERTY, originalValue);
      } else {
        System.clearProperty(JGuardAgent.CACHE_DIR_PROPERTY);
      }
    }
  }

  @Test
  @EnabledOnOs(OS.MAC)
  void getUserCacheDir_onMac_returnsHomeCache() {
    Path cacheDir = JGuardAgent.getUserCacheDir();

    assertThat(cacheDir.toString()).contains(".cache/jguard");
    assertThat(cacheDir.toString()).startsWith(System.getProperty("user.home"));
  }

  @Test
  @EnabledOnOs(OS.LINUX)
  void getUserCacheDir_onLinux_returnsHomeCache() {
    Path cacheDir = JGuardAgent.getUserCacheDir();

    // On Linux, should be ~/.cache/jguard or $XDG_CACHE_HOME/jguard
    String xdgCache = System.getenv("XDG_CACHE_HOME");
    if (xdgCache != null) {
      assertThat(cacheDir).isEqualTo(Path.of(xdgCache, "jguard"));
    } else {
      assertThat(cacheDir).isEqualTo(Path.of(System.getProperty("user.home"), ".cache", "jguard"));
    }
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void getUserCacheDir_onWindows_returnsLocalAppData() {
    Path cacheDir = JGuardAgent.getUserCacheDir();

    String localAppData = System.getenv("LOCALAPPDATA");
    if (localAppData != null) {
      assertThat(cacheDir).isEqualTo(Path.of(localAppData, "jguard", "cache"));
    } else {
      // Fallback to temp with username
      assertThat(cacheDir.toString()).contains("jguard-" + System.getProperty("user.name"));
    }
  }

  // ========== Cache File Name Tests ==========

  @Test
  void getCacheFileName_includesVersionAndHash() {
    String fileName = JGuardAgent.getCacheFileName();

    // Format: jguard-bootstrap-<version>-<hash>.jar
    // During unit tests, hash is "unknown" since bootstrap.jar resource isn't available
    assertThat(fileName).startsWith("jguard-bootstrap-" + Version.VERSION + "-");
    assertThat(fileName).endsWith(".jar");
    // Verify hash component exists (8 hex chars or "unknown")
    String withoutPrefix = fileName.replace("jguard-bootstrap-" + Version.VERSION + "-", "");
    String hash = withoutPrefix.replace(".jar", "");
    assertThat(hash).matches("([0-9a-f]{8}|unknown)");
  }

  @Test
  void getCacheFileName_isConsistent() {
    String fileName1 = JGuardAgent.getCacheFileName();
    String fileName2 = JGuardAgent.getCacheFileName();

    assertThat(fileName1).isEqualTo(fileName2);
  }

  // ========== JAR Validation Tests ==========

  @Test
  void isValidJarFile_withValidJar_returnsTrue() throws IOException {
    Path jarFile = createValidJarFile("valid.jar");

    assertThat(JGuardAgent.isValidJarFile(jarFile)).isTrue();
  }

  @Test
  void isValidJarFile_withNonExistentFile_returnsFalse() {
    Path nonExistent = tempDir.resolve("nonexistent.jar");

    assertThat(JGuardAgent.isValidJarFile(nonExistent)).isFalse();
  }

  @Test
  void isValidJarFile_withTextFile_returnsFalse() throws IOException {
    Path textFile = tempDir.resolve("notajar.jar");
    Files.writeString(textFile, "This is not a JAR file");

    assertThat(JGuardAgent.isValidJarFile(textFile)).isFalse();
  }

  @Test
  void isValidJarFile_withEmptyFile_returnsFalse() throws IOException {
    Path emptyFile = tempDir.resolve("empty.jar");
    Files.createFile(emptyFile);

    assertThat(JGuardAgent.isValidJarFile(emptyFile)).isFalse();
  }

  @Test
  void isValidJarFile_withCorruptedJar_returnsFalse() throws IOException {
    Path corruptedJar = tempDir.resolve("corrupted.jar");
    // Write partial JAR header (PK but incomplete)
    Files.write(corruptedJar, new byte[] {0x50, 0x4B, 0x03, 0x04, 0x00});

    assertThat(JGuardAgent.isValidJarFile(corruptedJar)).isFalse();
  }

  // ========== Security Validation Tests ==========

  @Test
  void isSecureAndValidJar_withValidJar_returnsTrue() throws IOException {
    Path jarFile = createValidJarFile("secure.jar");
    JGuardAgent.setSecurePermissions(jarFile);

    assertThat(JGuardAgent.isSecureAndValidJar(jarFile)).isTrue();
  }

  @Test
  void isSecureAndValidJar_withNonExistentFile_returnsFalse() {
    Path nonExistent = tempDir.resolve("nonexistent.jar");

    assertThat(JGuardAgent.isSecureAndValidJar(nonExistent)).isFalse();
  }

  @Test
  void isSecureAndValidJar_withInvalidJar_returnsFalse() throws IOException {
    Path invalidJar = tempDir.resolve("invalid.jar");
    Files.writeString(invalidJar, "not a jar");

    assertThat(JGuardAgent.isSecureAndValidJar(invalidJar)).isFalse();
  }

  @Test
  @DisabledOnOs(OS.WINDOWS) // Symlinks require admin on Windows
  void isSecureAndValidJar_withSymlink_returnsFalse() throws IOException {
    Path realJar = createValidJarFile("real.jar");
    Path symlink = tempDir.resolve("symlink.jar");
    Files.createSymbolicLink(symlink, realJar);

    assertThat(JGuardAgent.isSecureAndValidJar(symlink)).isFalse();
  }

  @Test
  @DisabledOnOs(OS.WINDOWS) // POSIX permissions not applicable
  void isSecureAndValidJar_withWorldWritable_returnsFalse() throws IOException {
    Path jarFile = createValidJarFile("world-writable.jar");

    // Make it world-writable
    PosixFileAttributeView posixView =
        Files.getFileAttributeView(jarFile, PosixFileAttributeView.class);
    if (posixView != null) {
      Set<PosixFilePermission> perms =
          Set.of(
              PosixFilePermission.OWNER_READ,
              PosixFilePermission.OWNER_WRITE,
              PosixFilePermission.OTHERS_WRITE);
      posixView.setPermissions(perms);
    }

    assertThat(JGuardAgent.isSecureAndValidJar(jarFile)).isFalse();
  }

  // ========== Permission Setting Tests ==========

  @Test
  @DisabledOnOs(OS.WINDOWS) // POSIX permissions not applicable
  void setSecurePermissions_onFile_setsOwnerOnly() throws IOException {
    Path file = tempDir.resolve("testfile.txt");
    Files.writeString(file, "test content");

    JGuardAgent.setSecurePermissions(file);

    PosixFileAttributeView posixView =
        Files.getFileAttributeView(file, PosixFileAttributeView.class);
    if (posixView != null) {
      Set<PosixFilePermission> perms = posixView.readAttributes().permissions();
      assertThat(perms)
          .containsExactlyInAnyOrder(
              PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
      assertThat(perms).doesNotContain(PosixFilePermission.GROUP_READ);
      assertThat(perms).doesNotContain(PosixFilePermission.GROUP_WRITE);
      assertThat(perms).doesNotContain(PosixFilePermission.OTHERS_READ);
      assertThat(perms).doesNotContain(PosixFilePermission.OTHERS_WRITE);
    }
  }

  @Test
  @DisabledOnOs(OS.WINDOWS) // POSIX permissions not applicable
  void setSecurePermissions_onDirectory_setsOwnerOnlyWithExecute() throws IOException {
    Path dir = tempDir.resolve("testdir");
    Files.createDirectory(dir);

    JGuardAgent.setSecurePermissions(dir);

    PosixFileAttributeView posixView =
        Files.getFileAttributeView(dir, PosixFileAttributeView.class);
    if (posixView != null) {
      Set<PosixFilePermission> perms = posixView.readAttributes().permissions();
      assertThat(perms)
          .containsExactlyInAnyOrder(
              PosixFilePermission.OWNER_READ,
              PosixFilePermission.OWNER_WRITE,
              PosixFilePermission.OWNER_EXECUTE);
      assertThat(perms).doesNotContain(PosixFilePermission.GROUP_READ);
      assertThat(perms).doesNotContain(PosixFilePermission.OTHERS_READ);
    }
  }

  @Test
  @DisabledOnOs(OS.WINDOWS)
  void setSecurePermissions_withInsecureFile_makesSecure() throws IOException {
    // Create file with insecure permissions (world-readable/writable)
    Path file = tempDir.resolve("insecure.txt");
    Files.writeString(file, "sensitive data");
    Set<PosixFilePermission> insecurePerms = PosixFilePermissions.fromString("rw-rw-rw-");
    Files.setPosixFilePermissions(file, insecurePerms);

    // Apply secure permissions
    JGuardAgent.setSecurePermissions(file);

    // Verify it's now secure
    Set<PosixFilePermission> newPerms = Files.getPosixFilePermissions(file);
    assertThat(newPerms).doesNotContain(PosixFilePermission.GROUP_READ);
    assertThat(newPerms).doesNotContain(PosixFilePermission.GROUP_WRITE);
    assertThat(newPerms).doesNotContain(PosixFilePermission.OTHERS_READ);
    assertThat(newPerms).doesNotContain(PosixFilePermission.OTHERS_WRITE);
  }

  // ========== Integration Tests ==========

  @Test
  void cachePathConstruction_isCorrect() {
    Path cacheDir = JGuardAgent.getUserCacheDir();
    String fileName = JGuardAgent.getCacheFileName();
    Path fullPath = cacheDir.resolve(fileName);

    assertThat(fullPath.getFileName().toString()).isEqualTo(fileName);
    assertThat(fullPath.getParent()).isEqualTo(cacheDir);
  }

  // ========== Helper Methods ==========

  private Path createValidJarFile(String name) throws IOException {
    Path jarFile = tempDir.resolve(name);
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    new JarOutputStream(new FileOutputStream(jarFile.toFile()), manifest).close();
    return jarFile;
  }
}
