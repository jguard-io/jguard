/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/**
 * Inspect embedded jGuard policy in a JAR or binary policy file.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard inspect mymodule.jar
 * jguard inspect policy.bin
 * </pre>
 */
@Command(
    name = "inspect",
    mixinStandardHelpOptions = true,
    description = "Inspect embedded policy in a JAR or policy file")
public final class InspectCommand implements Callable<Integer> {

  /** Standard location for embedded policies in JARs. */
  private static final String EMBEDDED_POLICY_PATH = "META-INF/jguard/policy.bin";

  @Spec private CommandSpec spec;

  @Parameters(index = "0", description = "Path to JAR file or policy.bin file")
  private Path path;

  @Option(
      names = {"-v", "--verbose"},
      description = "Enable verbose output (show entitlement details)")
  private boolean verbose;

  @Override
  public Integer call() {
    PrintWriter out = spec.commandLine().getOut();
    PrintWriter err = spec.commandLine().getErr();

    try {
      if (path.toString().endsWith(".jar")) {
        return inspectJar(out, err);
      } else {
        return inspectPolicyFile(out, err);
      }
    } catch (IOException e) {
      err.println("Error: " + e.getMessage());
      return 1;
    }
  }

  private int inspectJar(PrintWriter out, PrintWriter err) throws IOException {
    if (!Files.exists(path)) {
      err.println("Error: JAR file not found: " + path);
      return 1;
    }

    try (JarFile jar = new JarFile(path.toFile())) {
      JarEntry entry = jar.getJarEntry(EMBEDDED_POLICY_PATH);
      if (entry == null) {
        out.println("No embedded policy found in: " + path);
        out.println("  Expected location: " + EMBEDDED_POLICY_PATH);
        return 0;
      }

      out.println("JAR: " + path);
      out.println("Policy: " + EMBEDDED_POLICY_PATH);
      out.println();

      try (InputStream is = jar.getInputStream(entry)) {
        ApplicationPolicy policy = BinaryPolicyReader.readApplicationPolicy(is);
        printPolicy(out, policy);
      }
    }

    return 0;
  }

  private int inspectPolicyFile(PrintWriter out, PrintWriter err) throws IOException {
    if (!Files.exists(path)) {
      err.println("Error: Policy file not found: " + path);
      return 1;
    }

    out.println("Policy: " + path);
    out.println();

    try (InputStream is = Files.newInputStream(path)) {
      // Try reading as ApplicationPolicy (v2) first
      ApplicationPolicy policy = BinaryPolicyReader.readApplicationPolicy(is);
      printPolicy(out, policy);
    } catch (Exception e) {
      // Try reading as v1 PolicyDescriptor
      try {
        PolicyDescriptor descriptor = BinaryPolicyReader.fromFile(path);
        ApplicationPolicy policy = ApplicationPolicy.fromDescriptor(descriptor);
        printPolicy(out, policy);
      } catch (Exception e2) {
        err.println("Error reading policy: " + e.getMessage());
        return 1;
      }
    }

    return 0;
  }

  private void printPolicy(PrintWriter out, ApplicationPolicy policy) {
    out.println("Format version: " + policy.formatVersion());
    out.println("Modules: " + policy.modules().size());
    out.println();

    for (ModulePolicy module : policy.modules()) {
      out.println("  Module: " + module.moduleName());
      out.println("  Entitlements: " + module.entitlements().size());

      if (verbose) {
        for (Entitlement ent : module.entitlements()) {
          out.println("    - " + formatEntitlement(ent));
        }
      } else {
        // Just show capability names
        module.entitlements().stream()
            .map(e -> e.capability().name())
            .distinct()
            .sorted()
            .forEach(name -> out.println("    - " + name));
      }
      out.println();
    }
  }

  private String formatEntitlement(Entitlement ent) {
    StringBuilder sb = new StringBuilder();
    sb.append(ent.subject()).append(" -> ").append(ent.capability().name());
    if (!ent.capability().arguments().isEmpty()) {
      sb.append("(");
      for (int i = 0; i < ent.capability().arguments().size(); i++) {
        if (i > 0) sb.append(", ");
        sb.append(ent.capability().arguments().get(i));
      }
      sb.append(")");
    }
    return sb.toString();
  }
}
