# jGuard Gradle Plugin

The `io.jguard.policy` Gradle plugin compiles jGuard policy descriptors and provides
convenient tasks for running applications with agent enforcement.

## Installation

Add the plugin to your `build.gradle`:

```groovy
plugins {
    id "java"
    id "application"
    id "io.jguard.policy"
}
```

For composite builds, include the jGuard project in your `settings.gradle`:

```groovy
includeBuild("../jguard")
```

## Quick Start

1. Create a policy file at `src/main/java/module-info.jguard`:

```
security module com.example.myapp {
    // Grant filesystem read access to the entire module
    entitle module to fs.read("src", "**/*");

    // Grant network access to specific packages
    entitle com.example.myapp.http.. to network.outbound;
}
```

2. Run with agent enforcement:

```bash
./gradlew runWithAgent
```

## Tasks

### `compileJGuardPolicy`

Compiles `module-info.jguard` into binary format (`policy.bin`) and optionally
a human-readable JSON representation (`policy.json`).

```bash
./gradlew compileJGuardPolicy
```

Output files are placed in `build/generated/jguard/` by default.

### `runWithAgent`

Runs your application with the jGuard agent attached for runtime enforcement.
This task is only available when the `application` plugin is applied.

```bash
# Run with strict enforcement (default)
./gradlew runWithAgent

# Run in audit mode (log violations but don't block)
./gradlew runWithAgent -Pjguard.mode=audit

# Skip agent entirely (equivalent to ./gradlew run)
./gradlew runWithAgent -Pjguard.skip=true
```

## Configuration

Configure the plugin via the `jguardPolicy` extension:

```groovy
jguardPolicy {
    // Source policy file (default: src/main/java/module-info.jguard)
    sourceFile = file("src/main/jguard/module-info.jguard")

    // Output directory (default: build/generated/jguard)
    outputDir = layout.buildDirectory.dir("generated/jguard")

    // Include JSON representation (default: true)
    includeJson = true

    // Binary output filename (default: policy.bin)
    binName = "policy.bin"

    // JSON output filename (default: policy.json)
    jsonName = "policy.json"

    // Path within JAR for policy files (default: META-INF/jguard)
    jarPath = "META-INF/jguard"

    // Enforcement mode: strict, permissive, or audit (default: strict)
    mode = "strict"

    // Log level: error, warn, info, debug, trace (default: info)
    logLevel = "info"

    // Discovery mode: auto-discover policies from JARs (default: true)
    // Set to false for explicit single-module mode
    discoveryMode = true

    // Allow unsigned JARs during development (default: false)
    // WARNING: Never enable in production!
    allowUnsignedPolicies = false

    // Enable policy hot reload (default: false)
    hotReload = false

    // Hot reload poll interval in seconds (default: 5)
    hotReloadInterval = 5

    // External policies source directory (for grant/deny at deployment time)
    externalPoliciesSourceDir = file("policies-src")

    // External policies output directory (compiled .bin files)
    externalPoliciesOutputDir = file("policies")

    // Allow trusted modules (default: false)
    // WARNING: Trusted modules bypass ALL capability checks!
    allowTrusted = false
}
```

## Agent Dependency

The plugin automatically locates the jGuard agent JAR using these methods (in order):

1. **Explicit dependency** - Add to the `jguardAgent` configuration:
   ```groovy
   dependencies {
       jguardAgent("io.jguard:agent:1.0.0")
   }
   ```

2. **Composite build** - Auto-detected from `jguard/agent/build/libs/`

3. **Sibling directory** - Falls back to `../jguard/agent/build/libs/`

For composite builds, ensure the agent is built before running:

```groovy
tasks.named("runWithAgent") {
    dependsOn(gradle.includedBuild("jguard").task(":agent:jar"))
}
```

## Enforcement Modes

| Mode | Behavior |
|------|----------|
| `strict` | Deny unauthorized operations and throw `SecurityException` |
| `permissive` | Log violations but allow operations to proceed |
| `audit` | Log all operations (allowed and denied) without blocking |

Override the mode at runtime:

```bash
./gradlew runWithAgent -Pjguard.mode=audit
```

## Properties

| Property | Description |
|----------|-------------|
| `-Pjguard.mode=<mode>` | Override enforcement mode (strict, permissive, audit) |
| `-Pjguard.skip=true` | Disable agent entirely |

## External Policies

External policies allow modifying entitlements at deployment time using grant/deny semantics.

### Configuration

```groovy
jguardPolicy {
    // Source directory for .jguard files
    externalPoliciesSourceDir = file("policies-src")

    // Output directory for compiled .bin files
    externalPoliciesOutputDir = file("policies")

    // Allow external policies without signed JARs (dev only!)
    allowUnsignedPolicies = true
}
```

### Tasks

The plugin provides a `compileExternalPolicies` task:

```bash
./gradlew compileExternalPolicies
```

This compiles all `.jguard` files in the source directory to `.bin` files in the output directory.

### Directory Structure

```
my-app/
├── policies-src/              # Source .jguard files
│   ├── legacy.library.jguard  # Policy for third-party library
│   └── _global.jguard         # Global policy for all modules
├── policies/                  # Compiled .bin files (output)
│   ├── legacy.library.bin
│   └── _global.bin
└── build.gradle
```

## Hot Reload

Enable hot reload to update policies without restarting the application:

```groovy
jguardPolicy {
    hotReload = true
    hotReloadInterval = 5  // Poll every 5 seconds
}
```

When running with `./gradlew runWithAgent`, the agent will automatically detect policy file changes and reload them.

## Capabilities

jGuard supports the following capabilities:

| Capability | Arguments | Description |
|------------|-----------|-------------|
| `fs.read` | `(root, glob)` | Read files matching glob under root |
| `fs.write` | `(root, glob)` | Write files matching glob under root |
| `fs.hardlink` | `(root, glob)` | Create hard links matching glob under root |
| `network.outbound` | `(hostPattern?, portSpec?)` | Open outbound network connections |
| `network.listen` | `(portSpec?)` | Bind server sockets |
| `threads.create` | (none) | Create new threads |
| `native.load` | `(pattern?)` | Load native libraries |
| `env.read` | `(pattern?)` | Read environment variables |
| `system.property.read` | `(pattern?)` | Read system properties |
| `system.property.write` | `(pattern?)` | Write system properties |
| `process.exec` | `(pattern?)` | Execute external processes |
| `crypto.provider` | (none) | Modify JCE crypto providers |

### Example Policy

```
security module com.example.app {
    // Filesystem access
    entitle module to fs.read("/data", "**/*.json");
    entitle module to fs.write("/tmp", "**/*");

    // Network access
    entitle com.example.app.http.. to network.outbound("**.example.com", 443);
    entitle module to network.listen(8080);

    // Process execution (restricted to specific command)
    entitle com.example.app.spawner to process.exec("/usr/bin/java");

    // Deny dangerous operations for all code
    deny(defensive) module to crypto.provider;
    deny(defensive) module to native.load;
}
```

## Trusted Modules

Trusted modules bypass ALL capability checks. This is intended for native libraries
(e.g., PyTorch, TensorFlow) that require unrestricted access and cannot be modified.

### Configuration

```groovy
jguardPolicy {
    // Enable trusted module support
    allowTrusted = true

    // External policies for trusted module definitions
    externalPoliciesSourceDir = file("policies-src")
    externalPoliciesOutputDir = file("policies")
}
```

### Creating a Trusted Module Policy

Create a policy file for the native library in your external policies directory:

```
// File: policies-src/ai.djl.pytorch.jguard
security module ai.djl.pytorch {
    trusted;
}
```

Compile and run:

```bash
./gradlew compileExternalPolicies runWithAgent
```

### Security Warning

**Trusted modules are a significant security risk.** Only use them when:

1. The module is a native library that cannot be modified
2. You fully trust the library code
3. There is no alternative to using the library

The `allowTrusted` setting is `false` by default and must be explicitly enabled.

## JAR Packaging

When the Java plugin is applied, compiled policy files are automatically included
in the JAR under `META-INF/jguard/`:

```
your-app.jar
├── META-INF/
│   └── jguard/
│       ├── policy.bin
│       └── policy.json
└── ...
```

## Production Deployment

In production, run your application with the jGuard agent (no Gradle required).

### Auto-Discovery (Recommended)

The agent automatically discovers policies embedded in signed JARs:

```bash
# Just attach the agent - policies are discovered automatically!
java -javaagent:/path/to/jguard-agent.jar \
     -Djguard.mode=strict \
     -jar your-app.jar
```

### Explicit Policy File

For single-module apps or when you need an external policy file:

```bash
java -javaagent:/path/to/jguard-agent.jar=/path/to/policy.bin \
     -Djguard.mode=strict \
     -jar your-app.jar
```

### Policy Overrides

Operations teams can restrict policies at deployment time:

```bash
java -javaagent:jguard-agent.jar \
     -Djguard.policy.override=/etc/myapp/overrides \
     -jar your-app.jar
```

### JVM System Properties

| Property | Description | Default |
|----------|-------------|---------|
| `jguard.mode` | Enforcement mode (strict, permissive, audit) | strict |
| `jguard.log.level` | Logging level (error, warn, info, debug, trace) | info |
| `jguard.discovery` | Auto-discover policies from signed JARs | true |
| `jguard.allowUnsignedPolicies` | Allow unsigned JAR policies (dev only!) | false |
| `jguard.policy.override` | Directory for policy override files | — |
| `jguard.allow.trusted` | Allow trusted modules (bypass all checks) | false |
| `jguard.reload` | Enable policy hot reload | false |
| `jguard.reload.interval` | Hot reload poll interval in seconds | 5 |

## Example Project

See `samples/sandbox-demo/` for a complete working example:

```bash
cd samples/sandbox-demo
../../gradlew runWithAgent
```

## Troubleshooting

### Agent JAR not found

If you see "jGuard agent JAR not found", either:

1. Add an explicit dependency:
   ```groovy
   dependencies {
       jguardAgent("io.jguard:agent:VERSION")
   }
   ```

2. For composite builds, ensure the agent is built:
   ```bash
   ./gradlew :jguard:agent:jar
   ```

### Policy file not found

Ensure `compileJGuardPolicy` runs before `runWithAgent`:

```bash
./gradlew compileJGuardPolicy runWithAgent
```

Or add a dependency in your build script (the plugin does this automatically).
