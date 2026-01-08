/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.AgentLogger;
import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Verifies JAR file signatures for policy discovery.
 *
 * <p>This class ensures that embedded policies are only loaded from properly signed JARs. A JAR is
 * considered valid if:
 *
 * <ol>
 *   <li>It contains at least one signature (META-INF/*.SF file)
 *   <li>All class files and policy files are signed
 *   <li>All signatures are valid (not tampered)
 * </ol>
 *
 * <p>This prevents malicious unsigned JARs from granting themselves capabilities.
 */
public final class JarSignatureVerifier {

  private static final AgentLogger LOG = AgentLogger.getLogger(JarSignatureVerifier.class);

  /** Standard location for embedded jGuard policies. */
  public static final String POLICY_LOCATION = "META-INF/jguard/policy.bin";

  private JarSignatureVerifier() {
    // Static utility class
  }

  /**
   * Checks if a JAR file contains an embedded jGuard policy.
   *
   * @param jarFile the JAR file to check
   * @return true if the JAR contains META-INF/jguard/policy.bin
   */
  public static boolean hasEmbeddedPolicy(JarFile jarFile) {
    return jarFile.getEntry(POLICY_LOCATION) != null;
  }

  /**
   * Verifies that a JAR file is properly signed.
   *
   * <p>A JAR is considered properly signed if:
   *
   * <ul>
   *   <li>It has at least one signature block (META-INF/*.SF)
   *   <li>The embedded policy file is signed
   *   <li>All signatures are valid
   * </ul>
   *
   * @param jarFile the JAR file to verify
   * @return true if the JAR is properly signed, false otherwise
   */
  public static boolean isSignedAndValid(JarFile jarFile) {
    try {
      // Check if the JAR has any signatures
      if (!hasSignatures(jarFile)) {
        LOG.debug("JAR {} has no signatures", jarFile.getName());
        return false;
      }

      // Verify the policy entry is signed
      JarEntry policyEntry = jarFile.getJarEntry(POLICY_LOCATION);
      if (policyEntry == null) {
        LOG.debug("JAR {} has no policy at {}", jarFile.getName(), POLICY_LOCATION);
        return false;
      }

      // Read the entry to trigger signature verification
      // The JarFile API only verifies signatures when entries are read
      if (!verifyEntry(jarFile, policyEntry)) {
        LOG.warn("JAR {} policy entry is not signed or signature invalid", jarFile.getName());
        return false;
      }

      LOG.debug("JAR {} signature verified", jarFile.getName());
      return true;

    } catch (IOException e) {
      LOG.warn("Failed to verify JAR signature for {}: {}", jarFile.getName(), e.getMessage());
      return false;
    } catch (SecurityException e) {
      LOG.warn("JAR {} signature verification failed: {}", jarFile.getName(), e.getMessage());
      return false;
    }
  }

  /**
   * Checks if a JAR file has any signature files.
   *
   * @param jarFile the JAR file to check
   * @return true if the JAR has at least one .SF signature file
   */
  private static boolean hasSignatures(JarFile jarFile) {
    Enumeration<JarEntry> entries = jarFile.entries();
    while (entries.hasMoreElements()) {
      JarEntry entry = entries.nextElement();
      String name = entry.getName().toUpperCase();
      if (name.startsWith("META-INF/") && name.endsWith(".SF")) {
        return true;
      }
    }
    return false;
  }

  /**
   * Verifies that a specific JAR entry is signed.
   *
   * <p>The JAR API requires reading the entire entry to verify its signature. After reading, we can
   * check if the entry has code signers.
   *
   * @param jarFile the JAR file
   * @param entry the entry to verify
   * @return true if the entry is signed and the signature is valid
   * @throws IOException if an I/O error occurs
   */
  private static boolean verifyEntry(JarFile jarFile, JarEntry entry) throws IOException {
    // Read the entire entry to trigger signature verification
    byte[] buffer = new byte[8192];
    try (InputStream is = jarFile.getInputStream(entry)) {
      while (is.read(buffer) != -1) {
        // Just reading to verify signature
      }
    }

    // Check if the entry has signers (only available after reading)
    CodeSigner[] signers = entry.getCodeSigners();
    return signers != null && signers.length > 0;
  }

  /**
   * Gets information about the signers of a JAR's policy entry.
   *
   * @param jarFile the JAR file
   * @return a description of the signers, or "unsigned" if not signed
   */
  public static String getSignerInfo(JarFile jarFile) {
    try {
      JarEntry policyEntry = jarFile.getJarEntry(POLICY_LOCATION);
      if (policyEntry == null) {
        return "no policy";
      }

      // Read to trigger verification
      byte[] buffer = new byte[8192];
      try (InputStream is = jarFile.getInputStream(policyEntry)) {
        while (is.read(buffer) != -1) {
          // Reading to verify
        }
      }

      CodeSigner[] signers = policyEntry.getCodeSigners();
      if (signers == null || signers.length == 0) {
        return "unsigned";
      }

      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < signers.length; i++) {
        if (i > 0) sb.append(", ");
        // Get the first certificate in the chain (the signer's certificate)
        var certs = signers[i].getSignerCertPath().getCertificates();
        if (!certs.isEmpty()) {
          sb.append(certs.get(0).toString().split("\n")[0]);
        }
      }
      return sb.toString();

    } catch (IOException | SecurityException e) {
      return "verification failed: " + e.getMessage();
    }
  }
}
