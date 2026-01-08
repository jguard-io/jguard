/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSigner;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/**
 * List all jGuard policies found in JARs on a module path.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard list --module-path libs/
 * jguard list libs/
 * </pre>
 */
@Command(
    name = "list",
    mixinStandardHelpOptions = true,
    description = "List all policies found in JARs on a path")
public final class ListCommand implements Callable<Integer> {

  /** Standard location for embedded policies in JARs. */
  private static final String EMBEDDED_POLICY_PATH = "META-INF/jguard/policy.bin";

  @Spec private CommandSpec spec;

  @Parameters(index = "0", description = "Directory containing JAR files")
  private Path modulePath;

  @Option(
      names = {"-v", "--verbose"},
      description = "Enable verbose output (show entitlement counts)")
  private boolean verbose;

  @Option(
      names = {"--include-unsigned"},
      description = "Include policies from unsigned JARs")
  private boolean includeUnsigned;

  @Override
  public Integer call() {
    PrintWriter out = spec.commandLine().getOut();
    PrintWriter err = spec.commandLine().getErr();

    if (!Files.isDirectory(modulePath)) {
      err.println("Error: Not a directory: " + modulePath);
      return 1;
    }

    List<PolicyInfo> policies = new ArrayList<>();

    try (DirectoryStream<Path> stream = Files.newDirectoryStream(modulePath, "*.jar")) {
      for (Path jarPath : stream) {
        PolicyInfo info = inspectJar(jarPath, err);
        if (info != null) {
          if (info.signed || includeUnsigned) {
            policies.add(info);
          }
        }
      }
    } catch (IOException e) {
      err.println("Error reading directory: " + e.getMessage());
      return 1;
    }

    // Print results
    out.println("Module path: " + modulePath);
    out.println("Policies found: " + policies.size());
    if (!includeUnsigned) {
      out.println("(signed JARs only; use --include-unsigned for all)");
    }
    out.println();

    for (PolicyInfo info : policies) {
      out.println("  " + info.moduleName);
      out.println("    JAR: " + info.jarPath.getFileName());
      out.println("    Signed: " + (info.signed ? "yes" : "no"));
      if (verbose) {
        out.println("    Entitlements: " + info.entitlementCount);
      }
    }

    if (policies.isEmpty()) {
      out.println("  (no policies found)");
    }

    return 0;
  }

  private PolicyInfo inspectJar(Path jarPath, PrintWriter err) {
    try (JarFile jar = new JarFile(jarPath.toFile())) {
      JarEntry entry = jar.getJarEntry(EMBEDDED_POLICY_PATH);
      if (entry == null) {
        return null; // No policy in this JAR
      }

      // Check if JAR is signed by reading the policy entry
      // (signature verification happens during read)
      boolean signed = false;
      try (InputStream is = jar.getInputStream(entry)) {
        byte[] buffer = new byte[1024];
        while (is.read(buffer) != -1) {
          // Read entire entry to trigger signature verification
        }
      }

      // Check if the entry has code signers
      CodeSigner[] signers = entry.getCodeSigners();
      signed = signers != null && signers.length > 0;

      // Read the policy
      try (InputStream is = jar.getInputStream(entry)) {
        ApplicationPolicy policy = BinaryPolicyReader.readApplicationPolicy(is);
        if (policy.modules().isEmpty()) {
          return null;
        }
        ModulePolicy module = policy.modules().get(0);
        return new PolicyInfo(jarPath, module.moduleName(), signed, module.entitlements().size());
      }
    } catch (IOException e) {
      // Silently skip JARs that can't be read
      return null;
    }
  }

  private record PolicyInfo(
      Path jarPath, String moduleName, boolean signed, int entitlementCount) {}
}
