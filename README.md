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

* `fs.read(root, glob)`
* `fs.write(root, glob)`
* `network.outbound`
* `threads.create`
* `native.load`

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

## Status

jGuard is under active development.

The initial focus is on:

* a stable policy model
* filesystem and network enforcement
* clear failure semantics
* strong JPMS integration

---

## License

Apache 2.0

