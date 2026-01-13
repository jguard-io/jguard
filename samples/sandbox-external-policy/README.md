# External Policy Grant/Deny Demo

This demo showcases jGuard's **external policy** feature, which allows deployers to
modify module permissions at deployment time without changing the module's source code.

## The Scenario

Imagine you're deploying an application that uses a third-party library. The library's
embedded policy is **overly permissive** - it grants broad capabilities that you don't
want to allow in your deployment environment.

### The Problem: Overly Permissive Library

The `library` module simulates a third-party library with these embedded permissions:

```
security module io.jguard.samples.external.library {
    entitle module to network.outbound;    // ANY network access!
    entitle module to threads.create;       // Can spawn threads!
    entitle module to native.load;          // Can load native code! DANGEROUS!
    entitle module to fs.read("config", "**");
    entitle module to system.property.read;
}
```

This is problematic because:
- `network.outbound` to entire module allows the library to phone home or exfiltrate data
- `threads.create` for entire module could lead to resource exhaustion
- `native.load` is a significant security risk - arbitrary native code execution!

### The Solution: External Policies

External policies let you **deny** capabilities at deployment time:

**Global Policy (`_global.jguard`)** - Applies to ALL modules:
```
security global {
    deny module to native.load;                    // No module can load native code
    deny(defensive) module to system.property.write;  // Prevent property tampering
}
```

**Module-Specific Policy (`io.jguard.samples.external.library.jguard`)**:
```
security module io.jguard.samples.external.library {
    deny module to native.load;      // Revoke native loading
    deny module to threads.create;   // Revoke thread creation
}
```

## Running the Demo

### Prerequisites

Build the jGuard project from the repository root:

```bash
cd ../..
./gradlew build
```

### Step 1: Run Without jGuard (Baseline)

See what happens with no restrictions:

```bash
./gradlew :app:run
```

All operations succeed - this is the baseline behavior.

### Step 2: Run With jGuard + External Policies

The jGuard plugin automatically compiles and applies external policies when configured:

```bash
./gradlew :app:runWithAgent
```

That's it! The plugin:
1. Compiles external policy files from `policies-src/` to `policies/`
2. Passes `-Djguard.policy.override=policies/` to the agent automatically
3. Runs the application with both embedded and external policies merged

Now external policies **restrict** the library:
- Network access: **ALLOWED** (external policy doesn't deny it)
- Thread creation: **ALLOWED** (implementation note: executor threads bypass current instrumentation)
- Native loading: **BLOCKED** by jGuard! (both global and module policy deny it)
- Config reading: **ALLOWED** (legitimate, not denied)
- Property reading: **ALLOWED** (legitimate, not denied)

Sample output:
```
PolicyMerger - Module 'io.jguard.samples.external.library': 3 entitlements after merge (5 -> 3, delta -2)
...
[Library] Attempting to load native library: nonexistent
BootstrapEnforcer - DENIED NATIVE_LOAD: package=io.jguard.samples.external.library
[Library] ✗ BLOCKED by jGuard: access denied - not entitled to 'native.load'
```

## How It Works

### Merge Semantics

External policies use **grant/deny** semantics:

```
effective = (embedded ∪ external_grants ∪ global_grants) - (external_denials ∪ global_denials)
```

1. **Grants are additive**: External policies can add permissions not in embedded policy
2. **Denials are subtractive**: External policies can revoke embedded permissions
3. **Denials win**: If both grant and deny exist for same capability, deny wins

### Subject Pattern Matching

Denials match using subject pattern encompassing:

| Denial Subject | Matches Entitlements |
|----------------|---------------------|
| `module` | Any subject in the module |
| `pkg..` | `pkg..`, `pkg.*`, `pkg`, or any descendant |
| `pkg.*` | `pkg.*` or direct children |
| `pkg` | Only exact `pkg` match |

### File Structure

```
app/
├── policies-src/           # Human-readable policy sources
│   ├── _global.jguard      # Global policy (all modules)
│   └── io.jguard.samples.external.library.jguard
├── policies/               # Compiled binary policies (auto-generated)
│   ├── _global.bin
│   └── io.jguard.samples.external.library.bin
└── src/
    └── main/java/
        └── module-info.jguard  # App's embedded policy

library/
└── src/
    └── main/java/
        └── module-info.jguard  # Library's (overly permissive) embedded policy
```

### Configuration (build.gradle)

Using external policies is simple - just configure the source directory:

```groovy
plugins {
  id "application"
  id "io.jguard.policy"
}

jguardPolicy {
  allowUnsignedPolicies = true  // Development only!

  // Enable external policies
  externalPoliciesSourceDir = file("policies-src")
  externalPoliciesOutputDir = file("policies")
}
```

Then run `./gradlew runWithAgent` - the plugin handles everything else!

### Production: Signed JARs

For production deployments, jGuard requires **signed JARs** by default. This prevents
malicious code from embedding policies that grant itself dangerous capabilities.

1. **Remove `allowUnsignedPolicies = true`** from your build configuration
2. **Sign your JARs** using `jarsigner` after building:

```groovy
// In build.gradle - sign JAR after it's built
tasks.named("jar") {
  doLast {
    exec {
      commandLine "jarsigner",
        "-keystore", "/path/to/keystore.jks",
        "-storepass", "yourpassword",
        "-keypass", "yourkeypassword",
        archiveFile.get().asFile.absolutePath,
        "your-key-alias"
    }
  }
}
```

See the [sandbox-multimodule](../sandbox-multimodule) sample for a working example
with signed JARs.

## Use Cases

### 1. Restricting Third-Party Libraries

Deny dangerous capabilities from libraries you don't fully trust:

```
security module com.example.untrusted.lib {
    deny module to native.load;
    deny module to network.outbound;
}
```

### 2. Organization-Wide Security Policy

Global policies enforce organization standards:

```
security global {
    deny module to native.load;           // No native code
    deny module to system.property.write; // No property tampering
}
```

### 3. Expanding Library Permissions

Grant additional capabilities a library needs but doesn't have:

```
security module org.example.database {
    // Library's embedded policy only allows localhost
    // Grant production database access
    entitle module to network.outbound("db.prod.internal", 5432);
}
```

### 4. Defense in Depth

Use `deny(defensive)` to ensure capabilities are never granted:

```
security global {
    // Even if some module adds this in the future, deny it
    deny(defensive) module to system.exit;
}
```

## Related Documentation

- [External Policies](../../docs/spec/jguard-policy-descriptor.md#6-external-policies)
- [Agent Configuration](../../agent/README.md)
- [CLI Tool](../../cli/README.md)
