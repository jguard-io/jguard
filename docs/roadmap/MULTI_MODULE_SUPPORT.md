# Multi-Module Support Roadmap

## Overview

Enable jGuard to secure applications composed of multiple JPMS modules, each with its own policy, while supporting runtime policy overrides for operational flexibility.

## Design Decisions

### 1. Follows JPMS Semantics

jGuard mirrors JPMS module identity exactly:

| Deployment | Module Identity | Policy Source |
|------------|-----------------|---------------|
| Module path JAR | Named module (from `module-info.java`) | Embedded in JAR |
| Classpath JAR | Unnamed module (single, shared) | External file required |

- Each named module has its own `module-info.jguard` alongside `module-info.java`
- Policies are compiled and embedded in the signed JAR
- Enforcement uses caller's module identity from stack walking
- Unnamed module (classpath code) requires explicit external policy

### 2. Signature Verification Required

Embedded policies are only discovered from signed JARs:

| Mode | Behavior | Use case |
|------|----------|----------|
| **Default (strict)** | Only discover policies from signed JARs | Production |
| **Development** (`-Djguard.allowUnsignedPolicies=true`) | Discover from all JARs | Local dev/testing |

This prevents malicious JARs from granting themselves capabilities.

### 3. Duplicate Modules Fail Fast

If two JARs contain policies for the same module name, the agent fails at startup with a clear error:

```
Error: Duplicate policy for module 'com.example.foo' found in:
  - foo-1.0.jar
  - foo-2.0.jar
```

### 4. Layered Policy Model (v0.3+)

```
┌─────────────────────────────────────────┐
│  External policy (optional override)    │  ← hot-reloadable, can only RESTRICT
├─────────────────────────────────────────┤
│  Embedded policies (from JARs)          │  ← immutable, travels with code
└─────────────────────────────────────────┘
```

- Embedded policy = maximum capabilities the module *can* request
- External policy = what's *actually* granted in this deployment
- Effective = intersection (capability must be allowed by both)

---

## Multi-Module Example

**Project structure (e.g., example.com):**

```
com.example.core/
├── src/main/java/
│   ├── module-info.java              → module com.example.core
│   └── module-info.jguard            → entitlements for this module
└── build/libs/
    └── example-core-1.0.0.jar     (signed)
        ├── module-info.class
        └── META-INF/jguard/policy.bin

com.example.transport/
├── src/main/java/
│   ├── module-info.java              → module com.example.transport
│   └── module-info.jguard            → entitlements for this module
└── build/libs/
    └── example-transport-1.0.0.jar (signed)
        ├── module-info.class
        └── META-INF/jguard/policy.bin
```

**Runtime:**

```bash
java --module-path libs/ \
     -javaagent:jguard-agent.jar \
     -m com.example.server/com.example.Main
```

**Agent behavior:**

1. Scan module path for signed JARs with `META-INF/jguard/policy.bin`
2. Discover policies for all modules
3. Build `ApplicationPolicy` indexed by module name
4. On capability check:
   - Stack walk → caller's module name
   - Lookup policy for that module
   - Check entitlement → allow/deny

**Isolation guarantee:**

Each module's policy only grants capabilities to code *within that module*. Module A cannot grant capabilities to Module B.

---

## Milestones

### Milestone 1: Multi-Module Data Model ✅ COMPLETE

**Goal:** PolicyDescriptor supports multiple modules

**Status:** Completed

**Implemented:**
- `ModulePolicy` record for single module's entitlements
- `ApplicationPolicy` record as container for multi-module policies
- Binary format v2 with backward-compatible v1 reading
- `PolicyEnforcer` updated to work with `ApplicationPolicy`
- Module isolation: each module uses only its own entitlements
- Unnamed module handling for classpath code
- Comprehensive test coverage in `MultiModuleEnforcementTest`

**Changes:**

1. **New `ApplicationPolicy` record**

   File: `policy/src/main/java/io/jguard/policy/model/ApplicationPolicy.java`
   ```java
   public record ApplicationPolicy(
       int formatVersion,
       List<ModulePolicy> modules
   ) {
     public ModulePolicy getModule(String moduleName) { ... }
   }

   public record ModulePolicy(
       String moduleName,
       List<Entitlement> entitlements
   ) {}
   ```

2. **Binary format v2**
   - Header: `JGUARD\x00\x02` (version 2)
   - Module count (varint)
   - For each module: name length + name + entitlement count + entitlements
   - Backward compatible: v1 files read as single-module ApplicationPolicy

3. **PolicyEnforcer updates**
   - Constructor accepts `ApplicationPolicy`
   - Index entitlements by module name
   - `check()` looks up entitlements by `callerModule`

4. **Backward compatibility**
   - `PolicyDescriptor` (v1) still supported for single-module cases
   - Reader auto-detects version and returns appropriate type
   - Existing single-module apps continue to work

**Files to modify/create:**
- `policy/src/main/java/io/jguard/policy/model/ApplicationPolicy.java` (new)
- `policy/src/main/java/io/jguard/policy/model/ModulePolicy.java` (new)
- `policy/src/main/java/io/jguard/policy/serialization/BinaryPolicyWriter.java`
- `policy/src/main/java/io/jguard/policy/serialization/BinaryPolicyReader.java`
- `agent/src/main/java/io/jguard/agent/PolicyEnforcer.java`

**Tests:**
- Multi-module serialization round-trip
- PolicyEnforcer with multiple modules
- Cross-module access denied (module A can't use module B's entitlements)
- Backward compatibility (v1 files still work)
- Module lookup by name

---

### Milestone 2: Embedded Policy Discovery with Signature Verification

**Goal:** Agent discovers policies from signed JARs on module path

**Changes:**

1. **Standard embedding location**
   ```
   mymodule.jar (signed)
   └── META-INF/
       └── jguard/
           └── policy.bin
   ```

2. **PolicyDiscovery class**

   File: `agent/src/main/java/io/jguard/agent/PolicyDiscovery.java`
   ```java
   public final class PolicyDiscovery {

     public static ApplicationPolicy discoverEmbedded(AgentConfig config) {
       List<ModulePolicy> policies = new ArrayList<>();

       for (JarFile jar : findJarsWithEmbeddedPolicy()) {
         if (!config.allowUnsignedPolicies() && !isSignedAndValid(jar)) {
           LOG.warn("Skipping unsigned JAR: {}", jar.getName());
           continue;
         }

         ModulePolicy policy = readEmbeddedPolicy(jar);

         // Check for duplicates
         if (modulesSeen.contains(policy.moduleName())) {
           throw new PolicyException("Duplicate policy for module: " + policy.moduleName());
         }

         policies.add(policy);
       }

       return new ApplicationPolicy(FORMAT_VERSION, policies);
     }

     private static boolean isSignedAndValid(JarFile jar) {
       // Verify JAR signature using java.util.jar APIs
       // All entries must be signed, signatures must be valid
     }
   }
   ```

3. **AgentConfig updates**
   - Add `allowUnsignedPolicies` flag (default: false)
   - Add `unnamedModulePolicy` path for classpath code

4. **AgentInitializer updates**
   - If explicit policy path: use that (current behavior, single module)
   - If no explicit path: discover from signed JARs
   - Log discovered modules at startup

5. **Gradle plugin updates**
   - Embed compiled `policy.bin` in JAR at `META-INF/jguard/policy.bin`
   - New task: `embedJGuardPolicy` (runs after `compileJGuardPolicy`)

**Files to modify/create:**
- `agent/src/main/java/io/jguard/agent/PolicyDiscovery.java` (new)
- `agent/src/main/java/io/jguard/agent/JarSignatureVerifier.java` (new)
- `agent/src/main/java/io/jguard/agent/AgentInitializer.java`
- `bootstrap/src/main/java/io/jguard/bootstrap/AgentConfig.java`
- `gradle-plugin/src/main/java/io/jguard/gradle/policy/JGuardPolicyPlugin.java`

**Tests:**
- Discovery finds policies in multiple signed JARs
- Discovery skips unsigned JARs (default mode)
- Discovery includes unsigned JARs (dev mode)
- Discovery rejects tampered signed JARs
- Duplicate module detection fails fast
- Integration test with multi-module application

---

### Milestone 3: External Policy Overrides

**Goal:** Runtime policy restrictions via external files

**Changes:**

1. **New agent option**
   ```
   -Djguard.policy.override=/etc/myapp/overrides/
   ```

2. **Override directory structure**
   ```
   /etc/myapp/overrides/
   ├── com.example.core.bin       # Overrides for com.example.core
   ├── com.example.transport.bin  # Overrides for com.example.transport
   └── _global.bin                   # Applies to all modules
   ```

3. **Merge logic (restrictive)**
   ```java
   // Effective entitlement = embedded ∩ override
   // Override can only REMOVE capabilities, never add
   // Missing override file = embedded policy applies fully
   ```

4. **PolicyReloader updates**
   - Watch override directory for changes
   - Hot-reload on file changes
   - Atomic swap of merged policy

**Files to modify/create:**
- `agent/src/main/java/io/jguard/agent/PolicyMerger.java` (new)
- `agent/src/main/java/io/jguard/agent/PolicyReloader.java`
- `agent/src/main/java/io/jguard/agent/AgentInitializer.java`

**Tests:**
- Override restricts embedded capability
- Override cannot grant new capabilities
- Missing override file = full embedded policy
- Global override applies to all modules
- Hot-reload of overrides

---

### Milestone 4: CLI and Documentation

**Goal:** Tooling and docs for multi-module workflows

**Changes:**

1. **CLI commands**
   ```bash
   # Inspect embedded policy in a JAR
   jguard inspect mymodule.jar

   # List all policies in an application
   jguard list --module-path libs/

   # Diff two policies
   jguard diff embedded.bin override.bin

   # Validate override is subset of embedded
   jguard validate-override --jar mymodule.jar --override override.bin
   ```

2. **Documentation**
   - Multi-module tutorial
   - JAR signing guide for jGuard
   - Override configuration guide
   - Migration guide from v0.1

**Files to modify/create:**
- `cli/src/main/java/io/jguard/cli/InspectCommand.java` (new)
- `cli/src/main/java/io/jguard/cli/ListCommand.java` (new)
- `cli/src/main/java/io/jguard/cli/DiffCommand.java` (new)
- `cli/src/main/java/io/jguard/cli/ValidateOverrideCommand.java` (new)
- `docs/guides/multi-module.md` (new)
- `docs/guides/jar-signing.md` (new)
- `docs/guides/policy-overrides.md` (new)

---

## Release Plan

| Version | Milestones | Status | Delivers |
|---------|------------|--------|----------|
| **0.2.0** | 1 + 2 | Milestone 1 ✅ | Multi-module apps with embedded signed policies |
| **0.3.0** | 3 | Planned | External policy overrides (hot-reloadable) |
| **0.4.0** | 4 | Planned | CLI tools + full documentation |

## Migration from 0.1.x

**No breaking changes for single-module apps:**
- Existing `module-info.jguard` files work unchanged
- Existing `-javaagent:jguard.jar=/path/to/policy.bin` works unchanged
- v1 binary format still supported

**New for multi-module apps:**
- Each module gets its own `module-info.jguard` (next to `module-info.java`)
- Sign your JARs (required for policy discovery)
- No explicit policy path needed—agent discovers from signed JARs
- For classpath code: provide explicit policy via `-Djguard.policy.unnamed=...`
