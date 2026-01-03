# Internal document — *First Release Plan (Internal)*

> **Internal — not for README or public docs**

## Objective

Produce a credible **jGuard v0.1.0** that:

* enforces real security guarantees on JDK 21+
* is small, understandable, and auditable
* is suitable for open-source adoption
* can be integrated into a real plugin-based JVM system

---

## Non-goals for v0.1.0

* Full Java Security Manager parity
* Complete API coverage
* Reflection, classloading, or memory sandboxing
* Complex network filtering (hosts/ports)
* Container or OS integration

---

## Milestones

### M0 — Repository + CI

* Multi-module build
* JDK 21 baseline
* CI on 21+
* OSS hygiene

---

### M1 — Policy model + descriptor compiler

* `module-info.jguard` grammar + parser
* Deterministic policy model
* JSON renderer
* CLI compile tool
* Validation + golden tests

Exit criteria:

* identical input → identical output
* invalid policies rejected with good errors

---

### M2 — Java-backed descriptor (optional)

* Descriptor API
* Compilation to same model
* Parity tests

Exit criteria:

* `.jguard` and `.java` produce byte-identical policy metadata

---

### M3 — Enforcement v1 (filesystem) ✓

* Java agent
* Minimal hook surface
* Attribution via StackWalker
* Decision cache
* Deny-by-default semantics

Exit criteria:

* demonstrable block of unauthorized file access

---

### M3.1 — Agent Production Hardening ✓

The M3 agent is a proof-of-concept. M3.1 hardens it for production use.

#### 3.1.1 — Comprehensive Instrumentation ✓

Instrument all filesystem read entry points:

* `java.nio.file.Files` (done in M3) ✓
* `java.io.FileInputStream` — all constructors ✓
* `java.io.RandomAccessFile` — read-mode constructors ✓
* `java.nio.channels.FileChannel` — open methods ✓
* `java.io.FileReader` — all constructors ✓

Each requires careful bootstrap handling to avoid NoClassDefFoundError.

#### 3.1.2 — Robust Bootstrap Injection ✓

Replace hacky temp-dir injection with production-grade approach:

* Use `Instrumentation.appendToBootstrapClassLoaderSearch()` for pre-packaged bootstrap JAR ✓
* Proper cleanup of any temp resources ✓
* Fallback strategies if injection fails ✓
* Clear error messages on failure ✓

#### 3.1.3 — Module/Classloader Verification ✓

Current gap: any package matching entitlement is allowed regardless of module.

Fix:

* Track policy's module name ✓
* Verify caller's module matches policy module ✓
* Reject cross-module access attempts ✓
* Handle unnamed modules appropriately ✓

#### 3.1.4 — Graceful Error Handling ✓

Current: throws RuntimeException on any failure.

Production behavior:

* `EnforcementMode.STRICT` — fail closed, deny on errors ✓
* `EnforcementMode.PERMISSIVE` — fail open, allow on errors (for migration) ✓
* `EnforcementMode.AUDIT` — log but don't block (for testing) ✓
* Structured error context for debugging ✓

#### 3.1.5 — Built-in Logging ✓

Remove SLF4J dependency from bootstrap path:

* Simple console logger for agent internals ✓
* Optional SLF4J bridge when available ✓
* Log levels: ERROR, WARN, INFO, DEBUG, TRACE ✓
* System property control: `jguard.log.level` ✓

#### 3.1.6 — Agent Configuration ✓

System properties for runtime configuration:

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `jguard.policy` | path | (required) | Policy file location |
| `jguard.mode` | strict/permissive/audit | strict | Enforcement mode |
| `jguard.log.level` | error/warn/info/debug | info | Log verbosity |
| `jguard.log.denied` | true/false | true | Log denied operations |
| `jguard.log.allowed` | true/false | false | Log allowed operations |

#### 3.1.7 — Shadow JAR Isolation ✓

Prevent classpath conflicts:

* Relocate ByteBuddy to `org.jguard.internal.bytebuddy` ✓
* Relocate ASM to `org.jguard.internal.asm` ✓
* Keep only public API unrelocated ✓
* Test with apps using different ByteBuddy versions ✓

#### 3.1.8 — Caller Attribution Hardening ✓

Current gap: "unknown" caller fails open.

Production behavior:

* In STRICT mode, "unknown" caller → deny (JVM internal calls allowed) ✓
* Track caller's Module, not just package ✓
* Handle deep reflection scenarios ✓
* Detect and handle stack manipulation attempts ✓

Exit criteria:

* Agent works with real-world applications ✓
* No bypasses via FileInputStream/RandomAccessFile ✓
* Clear error messages for all failure modes ✓
* Configurable enforcement for migration scenarios ✓
* No classpath conflicts with app dependencies ✓

#### 3.1.9 — Gradle Plugin Enhancement ✓

* `runWithAgent` task for development convenience ✓
* `-Pjguard.mode` and `-Pjguard.skip` properties ✓
* Automatic agent JAR detection for composite builds ✓
* Full documentation in gradle-plugin/README.md ✓

#### 3.1.10 — Filesystem Write Enforcement ✓

* `fs.write` capability with root/glob matching ✓
* Instrumentation for:
  * `Files.write`, `Files.writeString`, `Files.newOutputStream`, `Files.newBufferedWriter` ✓
  * `Files.createFile`, `Files.createDirectory`, `Files.createDirectories` ✓
  * `Files.delete`, `Files.deleteIfExists` ✓
  * `FileOutputStream` constructors ✓
  * `FileWriter` constructors ✓
* Write callback in BootstrapEnforcer ✓
* Write check in PolicyEnforcer ✓
* Cross-platform (Windows/macOS/Linux) glob matching ✓

---

### M4 — Enforcement v1 (network) ✓

* Outbound network blocking ✓
* Minimal hook set ✓
* Clear failure messages ✓

Implementation:

* `network.outbound` capability (0 arguments) grants outbound TCP connection rights
* Instrumented classes:
  * `java.net.Socket` - constructors and connect() method
  * `java.nio.channels.SocketChannel` - connect() method
* BootstrapEnforcer.onNetworkConnect() callbacks for enforcement
* PolicyEnforcer.checkNetworkOutbound() for policy evaluation
* Retransformation support for bootstrap-loaded classes via DiscoveryStrategy.Reiterating

Exit criteria:

* demonstrable prevention of outbound socket creation ✓

---

### M4.1 — Network Listen Enforcement ✓

* `network.listen` capability grants server socket binding rights
  * `network.listen` (no arguments) - allows binding to any port
  * `network.listen(port)` (1 integer argument) - allows binding to specific port only
* Instrumented classes:
  * `java.net.ServerSocket` - constructors and bind() method
  * `java.nio.channels.ServerSocketChannel` - bind() method
* BootstrapEnforcer.onNetworkListen(port) callbacks for enforcement
* PolicyEnforcer.checkNetworkListen(context, port) for policy evaluation
* Separate from network.outbound for fine-grained control

Exit criteria:

* demonstrable prevention of unauthorized server socket creation ✓

---

### M5 — Integration proof

* One real plugin-style integration
* Policy-driven behavior change
* Install-time entitlement visibility

Exit criteria:

* real application runs with restricted privileges

---

### M6 — Release hardening

* Documentation
* Compatibility statement
* Versioned policy format
* `v0.1.0` tag + release notes

---

## Post-v0.1.0 Roadmap

### M7 — Policy Hot Reload

Enable policy updates without JVM restart:

* File watcher for policy.bin changes (configurable interval or inotify)
* Atomic PolicyEnforcer swap (volatile reference)
* Decision cache invalidation on reload
* Reload event logging and metrics
* Optional: SIGHUP trigger for manual reload

Implementation:

```java
// PolicyReloader watches for file changes
public class PolicyReloader {
  private final Path policyPath;
  private final AtomicReference<PolicyEnforcer> enforcerRef;

  public void onFileChanged() {
    PolicyDescriptor newPolicy = BinaryPolicyReader.fromFile(policyPath);
    PolicyEnforcer newEnforcer = new PolicyEnforcer(newPolicy, config);
    enforcerRef.set(newEnforcer);
    LOG.info("Policy reloaded: {}", policyPath);
  }
}
```

Exit criteria:

* Policy changes take effect within configurable interval (default: 5s)
* No restart required for entitlement updates
* Thread-safe reload with no missed enforcement

---

### M8 — Additional Capabilities

* `threads.create` — thread creation control
* `native.load` — native library loading control
* `process.exec` — subprocess execution control

These use existing category infrastructure (SIMPLE or TARGET_PATTERN).

---

### M9 — Reflection Control

* `reflect.invoke` — method invocation via reflection
* `reflect.access` — setAccessible() control
* Design decision: coarse (SIMPLE) vs fine-grained (TARGET_PATTERN with class patterns)

Instrumented APIs:

* `Method.invoke()`
* `Field.get/set()`
* `Constructor.newInstance()`
* `AccessibleObject.setAccessible()`
* `MethodHandle.invoke()` family

---

## Initial capability set (v0.1.0)

* `fs.read(root, glob)`
* `fs.write(root, glob)`
* `network.outbound`
* `network.listen`

Everything else deferred.

---

## Release bar

We ship when:

* policy is deterministic
* denial is reliable
* errors are understandable
* the surface area is small enough to reason about

