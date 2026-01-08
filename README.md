<p align="center">
  <img src="https://lucenia.io/wp-content/uploads/2026/01/JGuard-Logo-Name-1200x400-1.png" alt="jGuard" width="600">
</p>

<p align="center">
  <strong>Capability-based security for the modern JVM</strong>
</p>

<p align="center">
  <a href="https://github.com/jguard-io/jguard/actions/workflows/ci.yml"><img src="https://github.com/jguard-io/jguard/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a>
  <a href="https://github.com/jguard-io/jguard/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.oracle.com/java/technologies/javase/jdk21-archive-downloads.html"><img src="https://img.shields.io/badge/Java-21%2B-orange.svg" alt="Java 21+"></a>
  <a href="https://github.com/jguard-io/jguard/issues"><img src="https://img.shields.io/github/issues/jguard-io/jguard" alt="GitHub Issues"></a>
  <a href="https://github.com/jguard-io/jguard/pulls"><img src="https://img.shields.io/github/issues-pr/jguard-io/jguard" alt="GitHub Pull Requests"></a>
  <a href="https://github.com/jguard-io/jguard/graphs/contributors"><img src="https://img.shields.io/github/contributors/jguard-io/jguard" alt="Contributors"></a>
</p>

---

**jGuard is a capability-based security framework for the modern JVM (JDK 21+).**

jGuard enables JVM applications to run plugins, extensions, and embedded code with **explicit, least-privilege access** to sensitive resources such as the filesystem, network, threads, and native libraries.

Policies are declared declaratively using a **module-style descriptor** inspired by `module-info.java` and enforced at runtime with clear, auditable failure semantics.

---

## Why jGuard exists

Modern JVM applications increasingly execute code that is not fully trusted:

* plugins and extensions
* user-defined connectors
* embedded automation or agent runtimes
* long-lived, multi-tenant services

At the same time, the JVM no longer provides an in-process “deny by default” security boundary. Operating system sandboxing helps at the process boundary, but many applications need **in-JVM least privilege**:

> “This module may read from `data/models/**`, but may not open sockets or write files.”

jGuard addresses this need with a **capability-oriented security model** designed for the post–Security Manager JVM.

---

## Core ideas

jGuard is built around a small set of explicit principles:

### 1. No ambient authority

Code does not inherit access to sensitive resources implicitly.
All sensitive operations require an explicit capability.

### 2. Modules are the principal

JPMS module identity is the root of trust.
Packages refine privileges within a module.

### 3. Explicit capabilities

Security decisions are based on **what a module is allowed to do**, not on global permissions or stack inspection.

### 4. Deny by default

If a capability is not explicitly granted, the operation fails.

### 5. Deterministic and reviewable policy

Policies compile to deterministic metadata and can be rendered for human review and auditing.

---

## What jGuard is (and is not)

### jGuard is:

* A capability framework for JVM applications
* Designed for plugin-based and extensible systems
* Compatible with JDK 21 and newer
* Incrementally adoptable

### jGuard is not:

* A Java Security Manager replacement
* A full language sandbox
* A container or OS-level security system
* A blanket interceptor for all JVM APIs

jGuard complements OS-level isolation rather than replacing it.

---

## Policy format

### Canonical format: `module-info.jguard`

jGuard policies are authored using a simple descriptor format inspired by `module-info.java`.

Example:

```text
security module com.example.myplugin {
  entitle com.example.myplugin.http.. to network.outbound;
  entitle com.example.myplugin.io..   to fs.read(data, "models/**");
  entitle com.example.myplugin..      to threads.create;
  entitle module                      to fs.read(config, "**");
}
```

#### Package patterns

* `com.foo.bar` — exact package
* `com.foo.bar.*` — direct subpackages
* `com.foo.bar..` — recursive subpackages

---

### Optional Java-backed descriptor

For build environments that require Java-only sources, jGuard optionally supports a Java-backed descriptor that compiles to the same policy model.

```java
import static io.jguard.policy.Descriptor.*;

public final class security_policy {
  public static final Policy POLICY =
    module("com.example.myplugin",
      entitle("com.example.myplugin.http..", networkOutbound()),
      entitle("com.example.myplugin.io..",   fsRead(DATA, "models/**")),
      entitle("com.example.myplugin..",      threadsCreate()),
      entitle(MODULE,                        fsRead(CONFIG, "**"))
    );
}
```

Both formats compile to identical policy metadata.

---

## Capabilities

Capabilities represent explicit permission to perform sensitive operations.

Examples include:

* `fs.read(root, glob)` — read files matching glob pattern under root
* `fs.write(root, glob)` — write files matching glob pattern under root
* `network.outbound(hostPattern?, portSpec?)` — open outbound network connections with optional host/port filtering
* `network.listen(portSpec?)` — bind server sockets to ports (supports port ranges)
* `threads.create` — create new threads
* `native.load(pattern?)` — load native libraries
* `env.read(pattern?)` — read environment variables
* `system.property.read(pattern?)` — read system properties
* `system.property.write(pattern?)` — write system properties

**Host patterns** for `network.outbound`:
* `*` — matches one DNS segment (e.g., `*.example.com`)
* `**` — matches one or more DNS segments (e.g., `**.example.com`)

**Port specs** can be integers (`443`) or ranges (`"80-443"`).

Capabilities are intentionally narrow and composable.

---

## Enforcement model

jGuard enforces policy at a small number of high-impact guard points:

* filesystem access
* outbound network connections
* thread creation and management
* native library loading
* environment variable access
* system property access

At runtime:

1. A guarded operation is attempted
2. jGuard attributes the call to a `(module, package)`
3. The compiled policy is consulted
4. The operation is allowed or denied deterministically

Unauthorized access fails fast with a clear, auditable exception.

---

## Failure semantics

When a policy violation occurs, jGuard throws a deterministic exception describing:

* the attempted operation
* the calling module and package
* the missing capability

This makes violations actionable and debuggable rather than silent.

---

## Intended use cases

jGuard is designed for:

* extensible JVM servers
* plugin-based platforms
* embedded scripting or agent execution
* enterprise JVM applications requiring least-privilege execution

---

## Getting Started

### 1. Add the Gradle plugin and dependency

```groovy
plugins {
    id "java"
    id "application"
    id "io.jguard.policy"
}

dependencies {
    implementation("io.jguard:core")
}
```

### 2. Create a policy file

Create `src/main/java/module-info.jguard`:

```text
security module com.example.myapp {
    // Grant filesystem read access to all code in the module
    entitle module to fs.read("src", "**/*");
    entitle module to fs.read("config", "*.properties");

    // Grant network access only to specific packages
    entitle com.example.myapp.http.. to network.outbound;
}
```

### 3. Run with enforcement

```bash
# Development - with Gradle plugin
./gradlew runWithAgent

# Audit mode - log violations without blocking
./gradlew runWithAgent -Pjguard.mode=audit
```

### 4. Production deployment

For production, use an external policy file so administrators can update entitlements without rebuilding:

```bash
# Compile policy separately
jguard compile -o /etc/myapp/policy.bin module-info.jguard

# Run with external policy
java -javaagent:jguard-agent.jar=/etc/myapp/policy.bin \
     -Djguard.mode=strict \
     -jar your-app.jar
```

### 5. Policy hot reload (zero-downtime updates)

Enable hot reload to update entitlements without restarting the JVM:

```bash
java -javaagent:jguard-agent.jar=/etc/myapp/policy.bin \
     -Djguard.mode=strict \
     -Djguard.reload=true \
     -Djguard.reload.interval=5 \
     -jar your-app.jar
```

When enabled, the agent polls the policy file for changes. Update the policy and changes take effect automatically:

```bash
# Update policy - no restart needed!
jguard compile -o /etc/myapp/policy.bin updated-policy.jguard
# Changes detected and applied within 5 seconds
```

See [agent/README.md](agent/README.md) for full agent documentation and [gradle-plugin/README.md](gradle-plugin/README.md) for build integration.

---

## Multi-Module Support

jGuard supports JPMS multi-module applications where each module has its own security policy. **No configuration needed** — the agent automatically discovers policies from signed JARs.

### How it works

1. **Policy per module**: Each module has its own `module-info.jguard` next to `module-info.java`
2. **Policies embedded in JARs**: Compiled policies are embedded at `META-INF/jguard/policy.bin`
3. **Auto-discovery**: Agent automatically finds policies in signed JARs (no flags required)
4. **Module isolation**: Each module can only use its own entitlements (no cross-module access)

### Example Structure

```
my-app/
├── core/
│   └── src/main/java/
│       ├── module-info.java
│       └── module-info.jguard    # fs.read entitlements
├── network/
│   └── src/main/java/
│       ├── module-info.java
│       └── module-info.jguard    # network.outbound entitlements
└── app/
    └── src/main/java/
        ├── module-info.java
        └── module-info.jguard    # minimal entitlements (delegates to core/network)
```

### Running

```bash
# Just attach the agent - policies are discovered automatically
./gradlew :app:runWithAgent

# Or manually:
java -javaagent:jguard-agent.jar -jar myapp.jar
```

The agent discovers all module policies from signed JARs and enforces each module's entitlements independently.

### Development Mode

For local development with unsigned JARs:

```groovy
// app/build.gradle
jguardPolicy {
  allowUnsignedPolicies = true  // Only for development!
}
```

See [samples/sandbox-multimodule](samples/sandbox-multimodule) for a complete working example.

---

## Status

jGuard is ready for production use with comprehensive enforcement.

Completed:

* Stable policy model with deterministic compilation
* Comprehensive filesystem enforcement (`fs.read`, `fs.write`)
* Network enforcement (`network.outbound`, `network.listen`)
* Thread creation enforcement (`threads.create`)
* Native library loading enforcement (`native.load`)
* Environment variable access enforcement (`env.read`)
* System property access enforcement (`system.property.read`, `system.property.write`)
* Policy hot reload (update entitlements without restart)
* Clear failure semantics with configurable modes (STRICT, PERMISSIVE, AUDIT)
* Strong JPMS integration with module verification
* Single dispatch architecture for efficient capability checking
* **Multi-module support** with per-module policies and signed JAR verification

---

## License

Apache 2.0

