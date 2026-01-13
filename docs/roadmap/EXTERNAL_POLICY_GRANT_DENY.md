# External Policy with Grant/Deny Support

## Overview

Extend jGuard to support external `module-info.jguard` files that can both **grant** and **deny** entitlements, enabling:
- Granting permissions to non-JPMS libraries
- Granting forgotten permissions without re-releasing
- Restricting overly permissive upstream libraries
- Zero-downtime policy fixes via hot reload

---

## Requirements

| ID | Scenario | Solution |
|----|----------|----------|
| **a** | Non-JPMS upstream library (no `module-info.java`) | Deny all by default; external policy grants permissions |
| **b** | JPMS upstream library without jGuard (no embedded policy) | Same as (a) - deny all; external policy grants |
| **c** | JPMS + jGuard upstream with overly permissive embedded policy | External `deny` removes capabilities from embedded |
| **d** | Deny with no matching grant | Warning issued (suppressible with `deny(defensive)`) |
| **e** | Your own module, dev forgot permission | External `entitle` adds to embedded |
| **f** | Zero-downtime fixes | Hot reload (already built) applies to external policies |
| **g** | Environment-wide restrictions (e.g., airgapped) | `_global.jguard` applies to all modules |

---

## Grammar Changes

### Current Grammar (Unchanged)

```ebnf
PolicyFile:
    security module ModuleName { EntitlementDeclaration* }

EntitlementDeclaration:
    entitle Subject to Capability ;
```

### New Grammar Additions

```ebnf
PolicyFile:
    security module ModuleName { PolicyDeclaration* }

PolicyDeclaration:
    EntitlementDeclaration
    DenyDeclaration

DenyDeclaration:
    deny Subject to Capability ;
    deny ( defensive ) Subject to Capability ;
```

### New Tokens

| Token | Keyword |
|-------|---------|
| `DENY` | `deny` |
| `DEFENSIVE` | `defensive` |

---

## External Policy File Format

### Standard External Policy

```java
// /etc/myapp/policies/com.example.myapp.jguard

security module com.example.myapp {
    // Grant: adds to effective permissions (union)
    entitle com.example.myapp.reports.. to fs.write("/var/reports", "**");

    // Deny: removes from effective permissions (set difference)
    deny com.example.myapp.. to network.outbound;

    // Deny (defensive): suppress warning if capability not already granted
    deny(defensive) com.example.myapp.. to native.load;
}
```

### Global Policy (Applies to All Modules)

```java
// /etc/myapp/policies/_global.jguard

security module _global {
    // Deny network for ALL modules in this environment
    deny module to network.outbound;
    deny module to network.listen;
}
```

### Non-JPMS Library Policy

```java
// /etc/myapp/policies/org.locationtech.proj4j.jguard
// Uses package prefix as module name for non-JPMS libraries

security module org.locationtech.proj4j {
    entitle module to fs.read("/usr/share/proj", "**/*.txt");
}
```

---

## Directory Structure

```
/etc/myapp/policies/
├── _global.jguard                       # Applies to ALL modules
├── com.example.myapp.jguard             # Your app (add forgotten permission)
├── com.example.myapp.core.jguard        # Your core module (restrict something)
├── com.overly.permissive.lib.jguard     # Restrict OSS JPMS+jGuard library
└── org.locationtech.proj4j.jguard       # Grant to non-JPMS library
```

### File Naming Convention

| File Name | Applies To |
|-----------|------------|
| `_global.jguard` | All modules |
| `<module-name>.jguard` | Specific JPMS module |
| `<package-prefix>.jguard` | Non-JPMS code with matching package prefix |

---

## Agent Configuration

```bash
java -javaagent:jguard-agent.jar \
     -Djguard.policy.override=/etc/myapp/policies \
     -Djguard.reload=true \
     -Djguard.reload.interval=5 \
     -jar myapp.jar
```

### System Properties

| Property | Default | Description |
|----------|---------|-------------|
| `jguard.policy.override` | — | Directory containing external policy files |
| `jguard.reload` | `false` | Enable hot reload |
| `jguard.reload.interval` | `5` | Seconds between reload checks |

---

## Merge Logic

### Algorithm

```
For each module M:
  1. embedded_grants = grants from signed JAR (or empty if none)
  2. external_grants = grants from external file (or empty if none)
  3. global_grants = grants from _global.jguard (or empty if none)

  4. external_denials = denials from external file (or empty if none)
  5. global_denials = denials from _global.jguard (or empty if none)

  6. all_grants = embedded_grants ∪ external_grants ∪ global_grants
  7. all_denials = external_denials ∪ global_denials

  8. effective = all_grants - all_denials
```

### Formula

```
effective = (embedded ∪ external_grants ∪ global_grants) - (external_denials ∪ global_denials)
```

### Precedence

1. Denials always win over grants (if both exist for same capability)
2. More specific subject patterns do NOT override less specific (both apply)
3. Global policies merge with module-specific policies (not replace)

---

## Warning Logic

### Redundant Deny Warning

When a `deny` targets a capability that was never granted:

```
[WARN] [jguard] Redundant deny: com.example.foo.. -> threads.create (not in granted set)
```

**Suppression:** Use `deny(defensive)` to suppress this warning for intentional defensive denials.

### Unknown Module Warning

When an external policy file targets a module that isn't loaded:

```
[WARN] [jguard] External policy 'com.example.typo' does not match any loaded module
```

This catches typos while allowing forward-compatibility (policy for future module).

---

## Validation

### Compile-Time Validation (Always)

| Check | Severity | Description |
|-------|----------|-------------|
| Valid module name syntax | **Error** | Must be valid Java identifier |
| Valid package pattern syntax | **Error** | Must be valid package pattern |
| Known capability name | **Error** | Must be recognized capability |
| Valid capability arguments | **Error** | Correct types and counts |

### Runtime Validation (Always)

| Check | Severity | Description |
|-------|----------|-------------|
| Unknown module | **Warning** | External policy doesn't match loaded module |
| Redundant deny | **Warning** | Deny targets capability not in granted set |
| Redundant deny (defensive) | **Silent** | Suppressed by `deny(defensive)` |

### Compile-Time Validation (Strict Mode)

```bash
jguardc --strict -o policy.bin policy.jguard
```

In strict mode, warnings are treated as errors:

| Check | Severity (Default) | Severity (Strict) |
|-------|-------------------|-------------------|
| Redundant deny | **Warning** | **Error** |

Note: Redundant deny warnings can be suppressed with `deny(defensive)`.

---

## Non-JPMS Module Matching

For code on the classpath (unnamed module), jGuard matches by package prefix:

1. Caller package: `org.locationtech.proj4j.datum.GridShiftFile`
2. Look for external policy: `org.locationtech.proj4j.jguard`
3. Match: Policy module name is prefix of caller package
4. Apply grants/denials from that policy

### Matching Rules

| Caller Package | External Policy File | Match? |
|----------------|---------------------|--------|
| `org.locationtech.proj4j.datum.Foo` | `org.locationtech.proj4j.jguard` | Yes |
| `org.locationtech.proj4j.Foo` | `org.locationtech.proj4j.jguard` | Yes |
| `org.locationtech.other.Foo` | `org.locationtech.proj4j.jguard` | No |
| `org.locationtech.proj4jx.Foo` | `org.locationtech.proj4j.jguard` | No (not prefix) |

---

## Hot Reload

External policies are hot-reloadable (existing infrastructure):

1. `PolicyReloader` watches external policy directory
2. On file change, reloads all external policies
3. Recomputes effective policies using merge logic
4. Atomic swap of `PolicyEnforcer`
5. Warnings emitted for redundant denials / unknown modules

**Zero downtime** for:
- Adding forgotten grants
- Adding new denials
- Modifying existing policies
- Adding policies for new modules

---

## CLI Changes

### Compile Command

The `jguardc` compiler handles `deny` syntax:

```bash
# Compile external policy with deny statements
jguardc -o policy.bin external-policy.jguard
```

### Strict Mode

Use `--strict` to treat warnings as errors:

```bash
# Compile with strict validation (warnings become errors)
jguardc --strict -o policy.bin external-policy.jguard
```

This is useful in CI pipelines to catch redundant denies.

### Inspect Command

Updated to show denials:

```bash
jguard inspect policy.bin
```

Output:
```
Module: com.example.myapp
Grants: 3
  - module -> fs.read("/data", "**")
  - com.example.myapp.net.. -> network.outbound
  - com.example.myapp.worker.. -> threads.create
Denials: 1
  - module -> native.load
```

---

## Model Changes

### PolicyDescriptor (Updated)

```java
public record PolicyDescriptor(
    int formatVersion,
    String moduleName,
    List<Entitlement> entitlements,  // grants
    List<Denial> denials             // NEW
) {}
```

### Denial (New)

```java
public record Denial(
    SubjectPattern subject,
    CapabilityGrant capability,
    boolean defensive              // suppress warning if true
) {}
```

---

## Binary Format Changes

### Format Version

Denials are included in format version 2 (multi-module):

```
Header:
  magic:    4 bytes ("JGRD")
  version:  1 byte  (2 = multi-module with denials)

Module count: varint

For each module:
  name:          length-prefixed UTF-8
  entitlements:  count + repeated entitlement
  denials:       count + repeated denial

Denial:
  subjectType:   1 byte
  packageName:   string (if applicable)
  capability:    string
  argCount:      1 byte
  arguments:     repeated argument
  defensive:     1 byte (0 = false, 1 = true)
```

### Backward Compatibility

- Version 1 files: Read as before (single-module, no denials)
- Version 2 files: Multi-module with denial support

---

## Implementation Checklist

| Component | File | Change | Status |
|-----------|------|--------|--------|
| Lexer | `TokenType.java` | Add `DENY`, `DEFENSIVE` tokens | ✅ Done |
| Lexer | `Lexer.java` | Recognize new keywords | ✅ Done |
| Parser | `Parser.java` | Parse `deny` and `deny(defensive)` statements | ✅ Done |
| AST | `DenyDeclaration.java` | New AST node (mirrors `EntitlementDeclaration`) | ✅ Done |
| Model | `Denial.java` | New record for denial | ✅ Done |
| Model | `PolicyDescriptor.java` | Add `List<Denial> denials()` | ✅ Done |
| Model | `ModulePolicy.java` | Add `List<Denial> denials()` | ✅ Done |
| Model | `PolicyBuilder.java` | Build denials from AST | ✅ Done |
| Validator | `PolicyValidator.java` | Validate deny syntax and capabilities | ✅ Done |
| Serialization | `BinaryPolicyWriter.java` | Write denials in v2 format | ✅ Done |
| Serialization | `BinaryPolicyReader.java` | Read denials from v2 format | ✅ Done |
| Serialization | `JsonPolicyWriter.java` | Include denials in JSON output | ✅ Done |
| Tests | `ParserTest.java` | Test deny parsing | ✅ Done |
| Agent | `PolicyMerger.java` | Update merge logic: `(grants) - (denials)` | ✅ Done |
| Agent | `PolicyMerger.java` | Add redundant deny warning logic | ✅ Done |
| Agent | `PolicyMerger.java` | Unknown module warning | ✅ Done |
| Agent | `PolicyReloader.java` | Watch external directory (already supports it) | ✅ Done |
| CLI | `InspectCommand.java` | Display denials | ✅ Done |
| CLI | `JGuardc.java` | `--strict` flag | ✅ Done |
| Tests | `PolicyMergerTest.java` | Test merge logic and warnings | ✅ Done |
| Docs | Update READMEs, spec | Document new feature | ✅ Done |

---

## Effort Estimate

| Phase | Effort |
|-------|--------|
| Grammar + Parser + AST | 0.5 day |
| Model + Serialization | 0.5 day |
| PolicyMerger + Warnings | 1 day |
| External Policy Loading | 0.5 day |
| CLI Updates | 0.5 day |
| Testing | 1 day |
| Documentation | 0.5 day |
| **Total** | **~4-5 days** |

---

## Examples by Use Case

### (a) Non-JPMS Library Needs Permissions

```java
// /etc/myapp/policies/org.locationtech.proj4j.jguard
security module org.locationtech.proj4j {
    entitle module to fs.read("/usr/share/proj", "**/*.txt");
}
```

### (b) JPMS Library Without jGuard

```java
// /etc/myapp/policies/com.google.guava.jguard
security module com.google.guava {
    entitle com.google.common.cache.. to threads.create;
}
```

### (c) Restrict Overly Permissive Library

```java
// /etc/myapp/policies/com.overly.permissive.jguard
security module com.overly.permissive {
    // Library embedded policy grants network.outbound to module
    // We restrict it to only specific packages
    deny module to network.outbound;
    entitle com.overly.permissive.http.. to network.outbound;
}
```

### (d) Defensive Deny (Suppress Warning)

```java
// /etc/myapp/policies/com.example.myapp.jguard
security module com.example.myapp {
    // Ensure native loading is never allowed, even if future version grants it
    deny(defensive) module to native.load;
}
```

### (e) Dev Forgot Permission

```java
// /etc/myapp/policies/com.example.myapp.jguard
security module com.example.myapp {
    // Forgot this in the release, adding via external policy
    entitle com.example.myapp.export.. to fs.write("/var/exports", "**/*.csv");
}
```

### (g) Airgapped Environment

```java
// /etc/myapp/policies/_global.jguard
security module _global {
    // No network access for any module
    deny module to network.outbound;
    deny module to network.listen;

    // No native code
    deny(defensive) module to native.load;
}
```

---

## Release Plan

| Version | Content |
|---------|---------|
| **v0.2.0** | Milestones 1-4 (multi-module, CLI, current overrides) |
| **v0.2.1** | External policy grant/deny support (this plan) |
| **v0.3.0** | Documentation site + any deferred features |

---

## Replaces

This feature **replaces** the Milestone 3 override mechanism (separate `*.bin` files with intersection-only semantics) with a unified grant/deny approach that is:
- More expressive (can grant AND deny)
- Simpler to understand (one file format)
- Same directory structure (per-module files + `_global`)
