# Legacy Library Demo

This demo showcases jGuard's **restrictive by default** behavior with third-party
libraries that were **not built with jGuard**.

## The Scenario

You're using a third-party library from Maven Central (or an internal legacy library)
that has:
- **No jGuard policy** (not built with jGuard)
- **No JPMS module-info.java** (common for older libraries)

### The Problem: Unknown Code Capabilities

Without jGuard, you have no control over what the library does:
- Could it read arbitrary files?
- Could it make network connections (phone home, exfiltrate data)?
- Could it spawn threads and consume resources?
- Could it load native code?

### The Solution: Restrictive by Default + External Policies

jGuard's approach:
1. **Restrictive by default**: Libraries with no policy are BLOCKED from all
   sensitive operations
2. **Allowlisting via external policies**: Deployer explicitly grants only the
   capabilities the library needs

This is the **principle of least privilege** applied to dependencies.

## Project Structure

```
sandbox-legacy-library/
├── library/                    # Legacy library (NO jGuard, NO JPMS)
│   └── src/main/java/
│       └── io/jguard/samples/legacy/library/
│           └── LegacyLibrary.java
│   └── build/libs/
│       └── legacy-library.jar  # JAR name -> module name "legacy.library"
│
└── app/                        # Application (uses jGuard)
    ├── src/main/java/
    │   ├── module-info.java
    │   ├── module-info.jguard  # App's own policy
    │   └── io/jguard/samples/legacy/app/
    │       └── Main.java
    └── policies-src/           # External policies for legacy library
        └── legacy.library.jguard  # Filename matches auto-derived module name
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
cd samples/sandbox-legacy-library
./gradlew :app:run
```

All operations from the legacy library succeed - this is the **dangerous baseline**.

### Step 2: Run With jGuard (No External Policy)

First, let's see what happens when jGuard is enabled but no external policy grants
capabilities to the legacy library:

```bash
# Remove the external policy temporarily
mv app/policies-src/legacy.library.jguard /tmp/

# Run with jGuard
./gradlew :app:runWithAgent

# Restore the policy
mv /tmp/legacy.library.jguard app/policies-src/
```

**Result**: ALL operations from the legacy library are BLOCKED. This demonstrates
the "restrictive by default" principle - unknown code cannot do anything sensitive.

### Step 3: Run With jGuard + External Policy

Now run with the external policy that grants specific capabilities:

```bash
./gradlew :app:runWithAgent
```

**Result**: Only the explicitly granted capabilities work:
- `fs.read("config", "**")` - **ALLOWED** (granted by external policy)
- `system.property.read` - **ALLOWED** (granted by external policy)
- `network.outbound` - **BLOCKED** (not granted)
- `threads.create` - **BLOCKED** (not granted)

## The External Policy

The external policy (`app/policies-src/legacy.library.jguard`) grants only what
the library needs:

```
security module legacy.library {
    // Grant filesystem read for config files
    entitle module to fs.read("config", "**");

    // Grant system property read
    entitle module to system.property.read;

    // NOTE: We intentionally do NOT grant:
    // - network.outbound (library cannot phone home)
    // - threads.create (library cannot spawn threads)
    // - native.load (library cannot load native code)
}
```

## Key Differences from External-Policy Demo

| Aspect | sandbox-external-policy | sandbox-legacy-library |
|--------|------------------------|------------------------|
| Library has jGuard? | Yes (embedded policy) | No |
| Library has JPMS? | Yes | No |
| Default behavior | Library's embedded policy applies | All BLOCKED |
| External policy | Restricts (deny) | Grants (entitle) |
| Use case | Restrict overly permissive libs | Allowlist unknown code |

## How It Works

### Automatic Module Names

Since the legacy library has no `module-info.java`, Java derives an automatic
module name from the JAR filename:

1. Take the JAR filename: `legacy-library.jar`
2. Remove `.jar` extension: `legacy-library`
3. Convert hyphens to dots: `legacy.library`

The external policy file must match this derived module name: `legacy.library.jguard`

**Finding the module name for any JAR:**
```bash
jar --describe-module --file=some-library-1.2.3.jar
```

### Policy Merge Semantics

For modules with NO embedded policy:
- External policy entitlements are the ONLY entitlements
- No merge needed - external policy IS the policy

For modules WITH embedded policy (see sandbox-external-policy):
- External policy can add (entitle) or remove (deny) capabilities
- `effective = embedded + grants - denials`

## Production Considerations

1. **Audit dependencies**: Know what libraries you're using and what they need
2. **Start restrictive**: Grant no capabilities, then add as needed
3. **Use signed JARs**: Remove `allowUnsignedPolicies = true` in production
4. **Document grants**: Explain why each capability is granted

## Related Documentation

- [External Policies](../../docs/spec/jguard-policy-descriptor.md#6-external-policies)
- [sandbox-external-policy](../sandbox-external-policy) - Restricting jGuard-aware libraries
- [Agent Configuration](../../agent/README.md)
