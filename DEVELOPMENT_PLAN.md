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

* `network.outbound(host?, port?)` capability with optional host/port filtering
  * `network.outbound` - allows any host, any port
  * `network.outbound("*.example.com")` - host glob pattern, any port
  * `network.outbound("*", 443)` - any host, specific port
  * `network.outbound("*.example.com", "80-443")` - host pattern + port range
* Host glob patterns: `*` matches one DNS segment, `**` matches one or more
* Port specs: integer (`443`) or range string (`"80-443"`)
* Instrumented classes:
  * `java.net.Socket` - constructors and connect() method
  * `java.nio.channels.SocketChannel` - connect() method
* BootstrapEnforcer.onNetworkConnect(host, port) callbacks for enforcement
* PolicyEnforcer.checkNetworkOutbound(context, host, port) for policy evaluation
* Retransformation support for bootstrap-loaded classes via DiscoveryStrategy.Reiterating

Exit criteria:

* demonstrable prevention of outbound socket creation ✓
* demonstrable host/port filtering in sandbox-demo ✓

---

### M4.1 — Network Listen Enforcement ✓

* `network.listen(port?)` capability grants server socket binding rights
  * `network.listen` (no arguments) - allows binding to any port
  * `network.listen(8080)` (integer) - allows binding to specific port only
  * `network.listen("8080-8090")` (string range) - allows binding to port range
* Port specs: integer (`8080`) or range string (`"8080-8090"`)
* Instrumented classes:
  * `java.net.ServerSocket` - constructors and bind() method
  * `java.nio.channels.ServerSocketChannel` - bind() method
* BootstrapEnforcer.onNetworkListen(port) callbacks for enforcement
* PolicyEnforcer.checkNetworkListen(context, port) for policy evaluation
* Separate from network.outbound for fine-grained control

Exit criteria:

* demonstrable prevention of unauthorized server socket creation ✓

---

### M4.2 — Thread Creation Enforcement ✓

* `threads.create` capability grants thread creation rights
* Instrumented classes:
  * `java.lang.Thread` - start() method
* BootstrapEnforcer.onThreadCreate(threadName, threadId) callback
* PolicyEnforcer.checkThreadsCreate(context) for policy evaluation
* Package-scoped entitlements (e.g., `com.example.worker..`)

Exit criteria:

* demonstrable prevention of unauthorized thread creation ✓

---

### M4.3 — Native Library Loading Enforcement ✓

* `native.load` capability grants native library loading rights
  * `native.load` (no arguments) - allows loading any library
  * `native.load(pattern)` (1 string argument) - allows loading specific library patterns
* Instrumented classes:
  * `java.lang.System` - loadLibrary() and load() methods
  * `java.lang.Runtime` - loadLibrary() and load() methods
* BootstrapEnforcer.onNativeLoad(libraryName) callback
* PolicyEnforcer.checkNativeLoad(context, libraryName) for policy evaluation

Exit criteria:

* demonstrable prevention of unauthorized native library loading ✓

---

### M4.4 — Policy Hot Reload ✓

* Runtime policy updates without JVM restart
* Configuration via system properties:
  * `jguard.reload=true` - enable hot reload
  * `jguard.reload.interval=5` - poll interval in seconds
* Implementation:
  * `PolicyReloader` polls policy file for changes
  * Atomic swap of `PolicyEnforcer` via `AtomicReference`
  * Decision cache cleared on reload
* Graceful error handling for missing/corrupted policy files

Exit criteria:

* policy changes take effect without restart ✓
* corrupted policy files don't crash the agent ✓

---

### M4.5 — Bootstrap Refactoring (Single Dispatch) ✓

Refactored BootstrapEnforcer for maintainability and extensibility:

* Single dispatch architecture via `Operation` enum
* Unified `EnforcementCallback` interface
* Table-driven capability handling
* Configurable skip prefixes for caller attribution
* System.Logger for bootstrap logging (JDK-native)

Benefits:

* Adding new capability = enum entry + advice + handler
* ~600 lines reduced to ~250 lines
* No more duplication across capabilities

---

### M4.6 — Network Host/Port Filtering ✓

Enhanced `network.outbound` with host glob patterns and port range filtering:

* **Host glob patterns**:
  * `*` matches exactly one DNS segment (e.g., `*.example.com` matches `api.example.com`)
  * `**` matches one or more segments (e.g., `**.example.com` matches `a.b.c.example.com`)
  * Case-insensitive matching with IDN normalization
* **Port specifications**:
  * Integer: `443` for specific port
  * String range: `"80-443"` for port range
* New `HOST_PORT` operation category in bootstrap
* `HostMatcher` utility for segment-based DNS matching
* `PortRange` utility for port/range parsing and matching

Implementation files:

* `agent/src/main/java/org/jguard/agent/HostMatcher.java`
* `agent/src/main/java/org/jguard/agent/PortRange.java`
* Updated `PolicyValidator` for host/port semantic validation
* Updated `PolicyEnforcer` with HOST_PORT category handler

Exit criteria:

* demonstrable host pattern filtering (allow `*.example.com`, deny `evil.com`) ✓
* demonstrable port range filtering (allow `80-443`, deny `8080`) ✓
* sandbox-demo includes RestrictedNetworkClient example ✓

---

### M5 — Integration proof ✓

* `samples/sandbox-demo` demonstrates full integration
* Policy-driven behavior change across all 6 capabilities
* Entitled vs unentitled operations clearly demonstrated
* `./gradlew runWithAgent` for enforcement testing

Exit criteria:

* real application runs with restricted privileges ✓

---

### M6 — Release hardening ✓

* Documentation ✓
  * README.md - User overview with all capabilities
  * agent/README.md - Full instrumentation reference
  * gradle-plugin/README.md - Build integration guide
  * policy/README.md - Compiler internals and grammar
  * docs/spec/jguard-policy-descriptor.md - EBNF specification
  * samples/sandbox-demo/README.md - Getting started tutorial
* Compatibility statement ✓
* Versioned policy format (version 1) ✓
* Comprehensive test coverage ✓
  * PolicyEnforcerTest - all capability categories
  * PolicyReloaderTest - hot reload scenarios
  * EntitlementTest - sandbox-demo integration

Remaining for v0.1.0 release:

* `v0.1.0` tag + release notes
* Maven Central publication

---

## Initial capability set (v0.1.0) — COMPLETE ✓

| Capability | Status | Category |
|------------|--------|----------|
| `fs.read(root, glob)` | ✓ | FILESYSTEM |
| `fs.write(root, glob)` | ✓ | FILESYSTEM |
| `network.outbound(host?, port?)` | ✓ | HOST_PORT |
| `network.listen(port?)` | ✓ | PORT |
| `threads.create` | ✓ | SIMPLE |
| `native.load(pattern?)` | ✓ | TARGET_PATTERN |

Additional features:

| Feature | Status |
|---------|--------|
| Policy hot reload | ✓ |
| Enforcement modes (STRICT/PERMISSIVE/AUDIT) | ✓ |
| Single dispatch architecture | ✓ |
| Gradle plugin with runWithAgent | ✓ |
| Comprehensive documentation | ✓ |
| Network host/port filtering | ✓ |
| Port range support | ✓ |

---

## Release bar — MET ✓

| Criterion | Status |
|-----------|--------|
| Policy is deterministic | ✓ |
| Denial is reliable | ✓ |
| Errors are understandable | ✓ |
| Surface area is small enough to reason about | ✓ |

---

## Post-v0.1.0 Roadmap

### M7 — Process Execution Control

* `process.exec` capability for subprocess execution control
* Instrumented APIs:
  * `ProcessBuilder.start()`
  * `Runtime.exec()`
* Optional command pattern matching

---

### M8 — Reflection Control

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

### M9 — Additional Capabilities

Potential additions:

* `env.read` / `env.write` — environment variable access
* `classloader.create` — custom classloader creation
* `system.property.read` / `system.property.write` — system property access

