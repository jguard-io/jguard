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
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/**
 * Diff two jGuard policy files.
 *
 * <p>Shows entitlements that are in one file but not the other.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard diff embedded.bin override.bin
 * </pre>
 */
@Command(
    name = "diff",
    mixinStandardHelpOptions = true,
    description = "Compare two policy files and show differences")
public final class DiffCommand implements Callable<Integer> {

  @Spec private CommandSpec spec;

  @Parameters(index = "0", description = "Path to first (base) policy file")
  private Path basePath;

  @Parameters(index = "1", description = "Path to second (comparison) policy file")
  private Path comparePath;

  @Override
  public Integer call() {
    PrintWriter out = spec.commandLine().getOut();
    PrintWriter err = spec.commandLine().getErr();

    try {
      ApplicationPolicy basePolicy = loadPolicy(basePath, err);
      ApplicationPolicy comparePolicy = loadPolicy(comparePath, err);

      if (basePolicy == null || comparePolicy == null) {
        return 1;
      }

      boolean hasDifferences = false;

      // Compare each module in base policy
      for (ModulePolicy baseModule : basePolicy.modules()) {
        ModulePolicy compareModule = comparePolicy.getModule(baseModule.moduleName()).orElse(null);

        if (compareModule == null) {
          out.println("Module only in " + basePath.getFileName() + ": " + baseModule.moduleName());
          out.println();
          hasDifferences = true;
          continue;
        }

        // Find differences in entitlements
        Set<String> baseEntitlements = formatEntitlements(baseModule);
        Set<String> compareEntitlements = formatEntitlements(compareModule);

        Set<String> onlyInBase = new HashSet<>(baseEntitlements);
        onlyInBase.removeAll(compareEntitlements);

        Set<String> onlyInCompare = new HashSet<>(compareEntitlements);
        onlyInCompare.removeAll(baseEntitlements);

        if (!onlyInBase.isEmpty() || !onlyInCompare.isEmpty()) {
          out.println("Module: " + baseModule.moduleName());

          for (String ent : onlyInBase) {
            out.println("  - " + ent);
          }
          for (String ent : onlyInCompare) {
            out.println("  + " + ent);
          }
          out.println();
          hasDifferences = true;
        }
      }

      // Check for modules only in compare policy
      for (ModulePolicy compareModule : comparePolicy.modules()) {
        if (basePolicy.getModule(compareModule.moduleName()).isEmpty()) {
          out.println(
              "Module only in " + comparePath.getFileName() + ": " + compareModule.moduleName());
          out.println();
          hasDifferences = true;
        }
      }

      if (!hasDifferences) {
        out.println("Policies are identical.");
      }

      return 0;
    } catch (IOException e) {
      err.println("Error: " + e.getMessage());
      return 1;
    }
  }

  private ApplicationPolicy loadPolicy(Path path, PrintWriter err) throws IOException {
    if (!Files.exists(path)) {
      err.println("Error: File not found: " + path);
      return null;
    }

    try (InputStream is = Files.newInputStream(path)) {
      return BinaryPolicyReader.readApplicationPolicy(is);
    } catch (Exception e) {
      // Try v1 format
      try {
        PolicyDescriptor descriptor = BinaryPolicyReader.fromFile(path);
        return ApplicationPolicy.fromDescriptor(descriptor);
      } catch (Exception e2) {
        err.println("Error reading policy from " + path + ": " + e.getMessage());
        return null;
      }
    }
  }

  private Set<String> formatEntitlements(ModulePolicy module) {
    Set<String> result = new HashSet<>();
    for (Entitlement ent : module.entitlements()) {
      result.add(formatEntitlement(ent));
    }
    return result;
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
