# jGuard Multi-Module Sandbox Demo

This sample demonstrates jGuard's multi-module support, where each Java module has its own security policy and can only use its own entitlements.

## Project Structure

```
sandbox-multimodule/
├── core/                           # Core module with file system access
│   └── src/main/java/
│       ├── module-info.java        # JPMS module descriptor
│       ├── module-info.jguard      # jGuard policy (fs.read)
│       └── io/jguard/samples/multimodule/core/
│           └── ConfigReader.java   # File reading utility
├── network/                        # Network module with outbound access
│   └── src/main/java/
│       ├── module-info.java        # JPMS module descriptor
│       ├── module-info.jguard      # jGuard policy (network.outbound)
│       └── io/jguard/samples/multimodule/network/
│           └── SimpleHttpClient.java  # HTTP client utility
└── app/                            # Main application module
    └── src/main/java/
        ├── module-info.java        # JPMS module descriptor
        ├── module-info.jguard      # jGuard policy (minimal)
        └── io/jguard/samples/multimodule/app/
            └── Main.java           # Demo application
```

## Module Entitlements

Each module has specific, limited entitlements:

| Module | Entitlements | Purpose |
|--------|--------------|---------|
| `core` | `fs.read("config", "**")` | Read config files only |
| `network` | `network.outbound("httpbin.org", 443)` | Connect to httpbin.org:443 only |
| `app` | `threads.create`, `env.read("HOME")`, `env.read("USER")` | Minimal - must delegate |

## Key Concept: Module Isolation

The **app** module has no direct file or network entitlements. When it needs to:
- Read a file → delegates to **core** module's `ConfigReader`
- Make a network request → delegates to **network** module's `SimpleHttpClient`

This demonstrates the principle of least privilege - the main application code doesn't need (and shouldn't have) direct access to sensitive operations.

## Running the Demo

### Without jGuard Agent (baseline)
```bash
cd samples/sandbox-multimodule
../../gradlew :app:run
```

All operations will succeed because there's no enforcement.

### With jGuard Agent (enforced)
```bash
cd samples/sandbox-multimodule
../../gradlew :app:runWithAgent
```

You'll see:
- **ALLOWED**: Operations that go through entitled modules
- **BLOCKED**: Direct operations from the app module (no entitlements)

## Expected Output (with jGuard agent)

```
jGuard Multi-Module Demo
========================

This demo shows how jGuard enforces module-level security.
Each module has its own policy - cross-module access is blocked.

--- TEST 1: App Module Entitlements ---

[ENTITLED] env.read("HOME")
  SUCCESS: HOME = /Users/...

[NOT ENTITLED] env.read("PATH")
  BLOCKED (expected): jGuard: access denied - ... not entitled to 'env.read' (PATH)

--- TEST 2: Delegated File Reading (via core module) ---

[DELEGATED] ConfigReader.readConfig("app.conf")
  (Core module has fs.read entitlement for config/)
  SUCCESS: Read config = setting=value

--- TEST 3: Direct File Reading (from app module) ---

[NOT ENTITLED] Files.readString(Path.of("config/app.conf"))
  (App module does NOT have fs.read entitlement)
  BLOCKED (expected): jGuard: access denied - ... not entitled to 'fs.read' (config/app.conf)

--- TEST 4: Delegated Network Access (via network module) ---

[DELEGATED] SimpleHttpClient.tryConnect("httpbin.org", 443)
  (Network module has network.outbound entitlement for httpbin.org)
  Result: Connected successfully to httpbin.org:443

[DELEGATED] SimpleHttpClient.tryConnect("evil.com", 443)
  (Network module does NOT have entitlement for evil.com)
  Result: BLOCKED by jGuard: ... not entitled to 'network.outbound' (evil.com:443)

--- TEST 5: Direct Network Access (from app module) ---

[NOT ENTITLED] new Socket("httpbin.org", 443)
  (App module does NOT have network.outbound entitlement)
  BLOCKED (expected): jGuard: access denied - ... not entitled to 'network.outbound' (httpbin.org:443)

Demo complete!
```

## How It Works

1. **Policy per module**: Each module's `module-info.jguard` defines its entitlements
2. **Caller-based enforcement**: jGuard identifies which module is making each call
3. **No inheritance**: Entitlements don't flow across module boundaries
4. **Delegation pattern**: Modules without entitlements call entitled modules
5. **Signed JARs**: Policies are only loaded from signed JARs (by default)

## JAR Signing (Security)

jGuard requires JAR signatures by default to prevent policy tampering. This demo includes:

- **Test keystore**: `signing/test-keystore.jks` (self-signed certificate for testing)
- **Automatic signing**: JARs are signed during the build process

### Signature Verification Behavior

| Configuration | Signed JARs | Unsigned JARs |
|--------------|-------------|---------------|
| `allowUnsignedPolicies = false` (default) | Policies loaded | **Rejected** |
| `allowUnsignedPolicies = true` | Policies loaded | Policies loaded |

### For Production

1. **Create a real keystore** with a trusted certificate (or code signing cert)
2. **Sign your JARs** using `jarsigner` or Gradle signing plugin
3. **Keep `allowUnsignedPolicies = false`** (the secure default)

### For Development

You can enable unsigned policies for quick iteration:

```groovy
jguardPolicy {
  discoveryMode = true
  allowUnsignedPolicies = true  // NOT for production!
}
```

## Gradle Configuration

The main app module enables multi-module discovery:

```groovy
// app/build.gradle
jguardPolicy {
  discoveryMode = true
  // allowUnsignedPolicies defaults to false - requires signed JARs
}
```

## Files

- `core/src/main/java/module-info.jguard` - Core module policy
- `network/src/main/java/module-info.jguard` - Network module policy
- `app/src/main/java/module-info.jguard` - App module policy (minimal)
- `signing/test-keystore.jks` - Test keystore for JAR signing
