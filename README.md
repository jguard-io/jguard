## jGuard

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
import static org.jguard.policy.Descriptor.*;

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
* `network.outbound` — open outbound network connections
* `network.listen` — bind server sockets to ports
* `threads.create` — create new threads
* `native.load` — load native libraries

Capabilities are intentionally narrow and composable.

---

## Enforcement model

jGuard enforces policy at a small number of high-impact guard points:

* filesystem access
* outbound network connections
* thread creation and management
* native library loading

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
    id "org.jguard.policy"
}

dependencies {
    implementation("org.jguard:core")
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
jguard compile module-info.jguard -o /etc/myapp/policy.bin

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
jguard compile updated-policy.jguard -o /etc/myapp/policy.bin
# Changes detected and applied within 5 seconds
```

See [agent/README.md](agent/README.md) for full agent documentation and [gradle-plugin/README.md](gradle-plugin/README.md) for build integration.

---

## Status

jGuard is ready for production use with comprehensive enforcement.

Completed:

* Stable policy model with deterministic compilation
* Comprehensive filesystem enforcement (`fs.read`, `fs.write`)
* Network enforcement (`network.outbound`, `network.listen`)
* Thread creation enforcement (`threads.create`)
* Native library loading enforcement (`native.load`)
* Policy hot reload (update entitlements without restart)
* Clear failure semantics with configurable modes (STRICT, PERMISSIVE, AUDIT)
* Strong JPMS integration with module verification
* Single dispatch architecture for efficient capability checking

---

## License

Apache 2.0

