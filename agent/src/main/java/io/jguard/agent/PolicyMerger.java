/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.AgentLogger;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.Denial;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.SubjectPattern;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Merges embedded policies with external policies using grant/deny semantics.
 *
 * <p>External policies can both <b>grant</b> and <b>deny</b> capabilities:
 *
 * <ul>
 *   <li>Grants add to the effective policy (union)
 *   <li>Denials remove from the effective policy (set difference)
 *   <li>Denials always win over grants (if both exist for same capability)
 *   <li>Missing external file = embedded policy applies unchanged
 * </ul>
 *
 * <h2>Merge Formula</h2>
 *
 * <pre>
 * effective = (embedded ∪ external_grants ∪ global_grants) - (external_denials ∪ global_denials)
 * </pre>
 *
 * <h2>External Policy Directory Structure</h2>
 *
 * <pre>
 * /etc/myapp/policies/
 * ├── _global.bin                 # Global policy (applies to ALL modules)
 * ├── com.example.core.bin        # Policy for com.example.core module
 * ├── com.example.transport.bin   # Policy for com.example.transport module
 * └── org.locationtech.proj4j.bin # Policy for non-JPMS library by package prefix
 * </pre>
 *
 * <h2>Warning Logic</h2>
 *
 * <ul>
 *   <li><b>Redundant deny</b>: A deny targets a capability that was never granted. Use {@code
 *       deny(defensive)} to suppress this warning for intentional defensive denials.
 *   <li><b>Unknown module</b>: An external policy file targets a module that isn't loaded.
 * </ul>
 */
public final class PolicyMerger {

  private static final AgentLogger LOG = AgentLogger.getLogger(PolicyMerger.class);

  /** Filename for the global policy that applies to all modules. */
  public static final String GLOBAL_POLICY_FILENAME = "_global.bin";

  /** Legacy filename for backward compatibility. */
  @Deprecated public static final String GLOBAL_OVERRIDE_FILENAME = GLOBAL_POLICY_FILENAME;

  private PolicyMerger() {}

  /**
   * Merges an embedded policy with external policies from a directory.
   *
   * <p>The merge formula is: {@code effective = (embedded ∪ external_grants ∪ global_grants) -
   * (external_denials ∪ global_denials)}
   *
   * @param embedded the embedded policy (from signed JARs)
   * @param externalDir the directory containing external policy files
   * @return the merged policy with external policies applied
   * @throws IOException if reading external files fails
   */
  public static ApplicationPolicy merge(ApplicationPolicy embedded, Path externalDir)
      throws IOException {
    if (externalDir == null || !Files.isDirectory(externalDir)) {
      LOG.debug("No external policy directory, using embedded policy as-is");
      return embedded;
    }

    // Load global policy if present
    Optional<ModulePolicy> globalPolicy = loadExternalPolicy(externalDir, GLOBAL_POLICY_FILENAME);
    if (globalPolicy.isPresent()) {
      LOG.info(
          "Loaded global policy with {} entitlements and {} denials",
          globalPolicy.get().entitlements().size(),
          globalPolicy.get().denials().size());
    }

    // Load module-specific external policies
    Map<String, ModulePolicy> externalPolicies = new HashMap<>();
    for (ModulePolicy module : embedded.modules()) {
      String filename = module.moduleName() + ".bin";
      Optional<ModulePolicy> external = loadExternalPolicy(externalDir, filename);
      if (external.isPresent()) {
        externalPolicies.put(module.moduleName(), external.get());
        LOG.info(
            "Loaded external policy for module '{}' with {} entitlements and {} denials",
            module.moduleName(),
            external.get().entitlements().size(),
            external.get().denials().size());
      }
    }

    // Load external policies for modules that DON'T have embedded policies.
    // This allows external policies to grant capabilities to legacy libraries
    // that were not built with jGuard (no embedded policy).
    Map<String, ModulePolicy> newModulePolicies = loadNewModulePolicies(externalDir, embedded);

    // Check for external policies that don't match any module (warning only)
    checkUnknownModulePolicies(externalDir, embedded, externalPolicies, newModulePolicies);

    // If no external policies found, return embedded as-is
    if (globalPolicy.isEmpty() && externalPolicies.isEmpty() && newModulePolicies.isEmpty()) {
      LOG.debug("No external policy files found in {}, using embedded policy as-is", externalDir);
      return embedded;
    }

    // Merge each module using grant/deny semantics
    List<ModulePolicy> mergedModules = new ArrayList<>();
    for (ModulePolicy embeddedModule : embedded.modules()) {
      ModulePolicy merged =
          mergeModule(
              embeddedModule,
              externalPolicies.get(embeddedModule.moduleName()),
              globalPolicy.orElse(null));
      mergedModules.add(merged);

      int grantDelta = merged.entitlements().size() - embeddedModule.entitlements().size();
      if (grantDelta != 0) {
        LOG.info(
            "Module '{}': {} entitlements after merge ({} -> {}, delta {}{})",
            embeddedModule.moduleName(),
            merged.entitlements().size(),
            embeddedModule.entitlements().size(),
            merged.entitlements().size(),
            grantDelta >= 0 ? "+" : "",
            grantDelta);
      }
    }

    // Add new modules from external policies (legacy libraries without embedded policies)
    for (Map.Entry<String, ModulePolicy> entry : newModulePolicies.entrySet()) {
      ModulePolicy external = entry.getValue();
      // Apply global policy to new modules as well
      ModulePolicy merged = mergeNewModule(external, globalPolicy.orElse(null));
      mergedModules.add(merged);
      LOG.info(
          "Module '{}': {} entitlements from external policy (no embedded policy)",
          entry.getKey(),
          merged.entitlements().size());
    }

    // If global policy exists and has entitlements, create an "unnamed" module policy from it.
    // This ensures _global entitlements apply to classpath code (unnamed module).
    // Only create if global has entitlements - a global with only denials doesn't help unnamed.
    if (globalPolicy.isPresent() && !globalPolicy.get().entitlements().isEmpty()) {
      boolean hasUnnamedPolicy =
          mergedModules.stream()
              .anyMatch(m -> ApplicationPolicy.UNNAMED_MODULE.equals(m.moduleName()));
      if (!hasUnnamedPolicy) {
        ModulePolicy unnamedFromGlobal =
            new ModulePolicy(
                ApplicationPolicy.UNNAMED_MODULE,
                globalPolicy.get().entitlements(),
                globalPolicy.get().denials(),
                globalPolicy.get().trusted());
        mergedModules.add(unnamedFromGlobal);
        LOG.info(
            "Created 'unnamed' module policy from _global ({} entitlements)",
            unnamedFromGlobal.entitlements().size());
      }
    }

    return ApplicationPolicy.create(mergedModules);
  }

  /**
   * Merges a single module's embedded policy with external policies using grant/deny semantics.
   *
   * <p>Formula: {@code effective = (embedded ∪ external_grants ∪ global_grants) - (external_denials
   * ∪ global_denials)}
   *
   * @param embedded the embedded module policy
   * @param external the module-specific external policy (may be null)
   * @param global the global external policy (may be null)
   * @return the merged module policy
   */
  private static ModulePolicy mergeModule(
      ModulePolicy embedded, ModulePolicy external, ModulePolicy global) {
    // Step 1: Collect all grants (union)
    Set<Entitlement> allGrants = new HashSet<>(embedded.entitlements());
    if (external != null) {
      allGrants.addAll(external.entitlements());
    }
    if (global != null) {
      allGrants.addAll(global.entitlements());
    }

    // Step 2: Collect all denials (union)
    Set<Denial> allDenials = new HashSet<>();
    if (embedded.hasDenials()) {
      allDenials.addAll(embedded.denials());
    }
    if (external != null) {
      allDenials.addAll(external.denials());
    }
    if (global != null) {
      allDenials.addAll(global.denials());
    }

    // Step 3: Apply denials (set difference)
    // For each denial, remove matching entitlements
    Set<Entitlement> effective = new HashSet<>(allGrants);
    for (Denial denial : allDenials) {
      List<Entitlement> toRemove = findMatchingEntitlements(effective, denial);
      if (toRemove.isEmpty() && !denial.defensive()) {
        // Redundant deny warning (only for non-defensive denials)
        LOG.warn(
            "Redundant deny: {} -> {} (not in granted set)",
            denial.subject().toCanonicalString(),
            denial.capability().toCanonicalString());
      }
      effective.removeAll(toRemove);
    }

    // Note: We don't include denials in the merged ModulePolicy since they've been applied.
    // The merged policy represents the effective entitlements after all processing.
    return new ModulePolicy(embedded.moduleName(), new ArrayList<>(effective), List.of());
  }

  /**
   * Finds entitlements that match a denial.
   *
   * <p>A denial matches an entitlement if:
   *
   * <ul>
   *   <li>The capability names and arguments are equal
   *   <li>The denial's subject pattern encompasses the entitlement's subject
   * </ul>
   *
   * @param entitlements the set of entitlements to search
   * @param denial the denial to match against
   * @return list of matching entitlements
   */
  private static List<Entitlement> findMatchingEntitlements(
      Set<Entitlement> entitlements, Denial denial) {
    List<Entitlement> matches = new ArrayList<>();
    for (Entitlement entitlement : entitlements) {
      if (denialMatchesEntitlement(denial, entitlement)) {
        matches.add(entitlement);
      }
    }
    return matches;
  }

  /**
   * Checks if a denial matches an entitlement.
   *
   * <p>A denial matches if the capabilities are equal (name + arguments) and the denial's subject
   * pattern encompasses the entitlement's subject.
   */
  private static boolean denialMatchesEntitlement(Denial denial, Entitlement entitlement) {
    // Capability must match exactly (name + arguments)
    if (!denial.capability().equals(entitlement.capability())) {
      return false;
    }

    // Denial subject must encompass entitlement subject
    return subjectEncompasses(denial.subject(), entitlement.subject());
  }

  /**
   * Checks if the denial subject pattern encompasses the entitlement subject.
   *
   * <p>Encompassing rules:
   *
   * <ul>
   *   <li>MODULE encompasses everything (whole module denied)
   *   <li>PACKAGE_RECURSIVE encompasses same or child packages
   *   <li>PACKAGE_DIRECT_CHILDREN encompasses direct child packages
   *   <li>PACKAGE_EXACT encompasses only exact match
   * </ul>
   */
  private static boolean subjectEncompasses(SubjectPattern denial, SubjectPattern entitlement) {
    // MODULE denial encompasses everything
    if (denial.type() == SubjectPattern.Type.MODULE) {
      return true;
    }

    // For package-based denials, we need to compare against the entitlement subject
    String denialPkg = denial.packageName();
    String entitlementPkg =
        entitlement.type() == SubjectPattern.Type.MODULE ? null : entitlement.packageName();

    return switch (denial.type()) {
      case MODULE -> true; // Already handled above, but for completeness
      case PACKAGE_EXACT -> {
        // Exact package denial only matches exact entitlement
        if (entitlement.type() == SubjectPattern.Type.MODULE) {
          yield false; // Can't deny a module-wide grant with exact package
        }
        yield denialPkg.equals(entitlementPkg)
            && entitlement.type() == SubjectPattern.Type.PACKAGE_EXACT;
      }
      case PACKAGE_DIRECT_CHILDREN -> {
        // Direct children denial matches:
        // - Same direct children pattern
        // - Exact packages that are direct children of denial package
        if (entitlement.type() == SubjectPattern.Type.MODULE) {
          yield false;
        }
        if (entitlement.type() == SubjectPattern.Type.PACKAGE_DIRECT_CHILDREN) {
          yield denialPkg.equals(entitlementPkg);
        }
        if (entitlement.type() == SubjectPattern.Type.PACKAGE_EXACT) {
          // Check if entitlement package is a direct child of denial package
          yield isDirectChild(denialPkg, entitlementPkg);
        }
        yield false;
      }
      case PACKAGE_RECURSIVE -> {
        // Recursive denial matches:
        // - Same or narrower recursive patterns
        // - Any pattern within the recursive scope
        if (entitlement.type() == SubjectPattern.Type.MODULE) {
          yield false;
        }
        // Check if entitlement package is within denial's recursive scope
        yield entitlementPkg.equals(denialPkg) || entitlementPkg.startsWith(denialPkg + ".");
      }
    };
  }

  /**
   * Checks if child is a direct child package of parent.
   *
   * @param parent the parent package (e.g., "com.example")
   * @param child the potential child package (e.g., "com.example.sub")
   * @return true if child is a direct child of parent
   */
  private static boolean isDirectChild(String parent, String child) {
    if (!child.startsWith(parent + ".")) {
      return false;
    }
    String remainder = child.substring(parent.length() + 1);
    return !remainder.contains(".");
  }

  /**
   * Loads external policies for modules that don't have embedded policies.
   *
   * <p>This allows external policies to grant capabilities to legacy libraries that were not built
   * with jGuard. Scans the external directory for .bin files that don't match any embedded module.
   *
   * @param externalDir the external policy directory
   * @param embedded the embedded policy (to check which modules already have policies)
   * @return map of module name to external policy for new modules
   * @throws IOException if reading files fails
   */
  private static Map<String, ModulePolicy> loadNewModulePolicies(
      Path externalDir, ApplicationPolicy embedded) throws IOException {
    Set<String> embeddedModules = new HashSet<>();
    for (ModulePolicy module : embedded.modules()) {
      embeddedModules.add(module.moduleName());
    }

    Map<String, ModulePolicy> newPolicies = new HashMap<>();

    // Scan for .bin files that don't match embedded modules
    try (var stream = Files.list(externalDir)) {
      List<Path> candidates =
          stream
              .filter(Files::isRegularFile)
              .filter(p -> p.getFileName().toString().endsWith(".bin"))
              .filter(p -> !p.getFileName().toString().equals(GLOBAL_POLICY_FILENAME))
              .toList();

      for (Path path : candidates) {
        String filename = path.getFileName().toString();
        String moduleName = filename.substring(0, filename.length() - 4); // Remove .bin

        // Skip if this module already has an embedded policy
        if (embeddedModules.contains(moduleName)) {
          continue;
        }

        // Load the external policy for this new module
        Optional<ModulePolicy> policy = loadExternalPolicy(externalDir, filename);
        if (policy.isPresent()) {
          newPolicies.put(moduleName, policy.get());
          LOG.info(
              "Loaded external policy for legacy module '{}' ({} entitlements, {} denials)",
              moduleName,
              policy.get().entitlements().size(),
              policy.get().denials().size());
        }
      }
    }

    return newPolicies;
  }

  /**
   * Merges a new module (from external policy only) with global policy.
   *
   * <p>This is for modules that have no embedded policy - the external policy becomes the base, and
   * global denials still apply.
   *
   * @param external the external policy for the new module
   * @param global the global policy (may be null)
   * @return the merged module policy
   */
  private static ModulePolicy mergeNewModule(ModulePolicy external, ModulePolicy global) {
    if (global == null) {
      return external;
    }

    // Apply global grants and denials to the external policy
    Set<Entitlement> allGrants = new HashSet<>(external.entitlements());
    allGrants.addAll(global.entitlements());

    Set<Denial> allDenials = new HashSet<>();
    if (external.hasDenials()) {
      allDenials.addAll(external.denials());
    }
    allDenials.addAll(global.denials());

    // Apply denials
    Set<Entitlement> effective = new HashSet<>(allGrants);
    for (Denial denial : allDenials) {
      List<Entitlement> toRemove = findMatchingEntitlements(effective, denial);
      effective.removeAll(toRemove);
    }

    return new ModulePolicy(external.moduleName(), List.copyOf(effective), List.of());
  }

  private static void checkUnknownModulePolicies(
      Path externalDir,
      ApplicationPolicy embedded,
      Map<String, ModulePolicy> loadedExternal,
      Map<String, ModulePolicy> newModulePolicies)
      throws IOException {
    Set<String> knownModules = new HashSet<>();
    for (ModulePolicy module : embedded.modules()) {
      knownModules.add(module.moduleName());
    }

    // Scan for .bin files in the external directory
    try (var stream = Files.list(externalDir)) {
      stream
          .filter(Files::isRegularFile)
          .filter(p -> p.getFileName().toString().endsWith(".bin"))
          .forEach(
              path -> {
                String filename = path.getFileName().toString();
                if (filename.equals(GLOBAL_POLICY_FILENAME)) {
                  return; // Global policy is expected
                }

                String moduleName = filename.substring(0, filename.length() - 4); // Remove .bin
                // Now also check newModulePolicies - these are valid, not unknown
                if (!knownModules.contains(moduleName)
                    && !loadedExternal.containsKey(moduleName)
                    && !newModulePolicies.containsKey(moduleName)) {
                  LOG.warn("External policy '{}' could not be loaded", path.getFileName());
                }
              });
    }
  }

  /**
   * Loads an external policy from a file in the external policy directory.
   *
   * @param externalDir the external policy directory
   * @param filename the policy filename
   * @return the loaded policy, or empty if file doesn't exist
   * @throws IOException if reading fails
   */
  private static Optional<ModulePolicy> loadExternalPolicy(Path externalDir, String filename)
      throws IOException {
    Path policyPath = externalDir.resolve(filename);
    if (!Files.exists(policyPath)) {
      return Optional.empty();
    }

    LOG.debug("Loading external policy from: {}", policyPath);
    byte[] bytes = Files.readAllBytes(policyPath);
    ApplicationPolicy policy =
        BinaryPolicyReader.readApplicationPolicy(new ByteArrayInputStream(bytes));

    // External policy file should contain exactly one module policy
    if (policy.modules().isEmpty()) {
      LOG.warn("External policy file {} is empty, ignoring", filename);
      return Optional.empty();
    }
    if (policy.modules().size() > 1) {
      LOG.warn("External policy file {} contains multiple modules, using first", filename);
    }

    return Optional.of(policy.modules().get(0));
  }

  /**
   * Result of merge validation, including any warnings generated.
   *
   * @param redundantDenials denials that didn't match any grant (non-defensive only)
   * @param unknownModules external policies that didn't match any loaded module
   */
  public record MergeWarnings(List<Denial> redundantDenials, List<String> unknownModules) {

    /** Returns true if there are any warnings. */
    public boolean hasWarnings() {
      return !redundantDenials.isEmpty() || !unknownModules.isEmpty();
    }
  }
}
