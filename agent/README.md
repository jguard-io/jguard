# jGuard Agent

The jGuard Java agent enforces capability-based security policies at runtime by instrumenting JDK classes.

## Quick Start

```bash
java -javaagent:jguard-agent.jar=/path/to/policy.bin -jar myapp.jar
```

## How It Works

The agent uses ByteBuddy to instrument JDK filesystem and network classes, intercepting operations and checking them against compiled policy files.

### Enforcement Flow

1. Application calls `Files.readString(path)` (or similar)
2. ByteBuddy advice intercepts the call
3. `BootstrapEnforcer` identifies the caller package via StackWalker
4. `PolicyEnforcer` checks if the package is entitled to `fs.read` for that path
5. If entitled, operation proceeds; otherwise, `SecurityException` is thrown

### Architecture

The agent uses a two-module architecture for proper classloader handling:

- **agent-bootstrap**: Classes injected into the bootstrap classloader (no external dependencies)
- **agent**: Main agent code with ByteBuddy and policy enforcement

This separation is necessary because advice woven into JDK classes can only reference classes on the bootstrap classpath.

## Configuration

### Agent Argument

```bash
-javaagent:jguard-agent.jar=/path/to/policy.bin
```

### External Policy Files (Recommended for Production)

For production deployments, keep policy files external to the application JAR. This allows administrators to update entitlements without rebuilding the application:

```bash
# 1. Compile policy separately
jguardc -o /etc/myapp/policy.bin src/main/java/module-info.jguard

# 2. Run application with external policy
java -javaagent:jguard-agent.jar=/etc/myapp/policy.bin -jar myapp.jar

# 3. Update entitlements (requires restart, no rebuild)
jguardc -o /etc/myapp/policy.bin updated-policy.jguard
systemctl restart myapp
```

This separation enables:
- **Security team** manages policy files independently
- **Dev team** ships application without embedded policies
- **Ops team** updates entitlements without rebuilding artifacts

### System Properties

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `jguard.policy` | path | — | Explicit policy file (disables auto-discovery) |
| `jguard.mode` | strict/permissive/audit | strict | Enforcement mode |
| `jguard.log.level` | error/warn/info/debug/trace | info | Log verbosity |
| `jguard.log.denied` | true/false | true | Log denied operations |
| `jguard.log.allowed` | true/false | false | Log allowed operations |
| `jguard.reload` | true/false | false | Enable policy hot reload |
| `jguard.reload.interval` | seconds | 5 | Hot reload poll interval |
| `jguard.discovery` | true/false | **true** | Auto-discover policies from signed JARs |
| `jguard.allowUnsignedPolicies` | true/false | false | Allow unsigned JAR policies (dev only!) |
| `jguard.policy.override` | path | — | Directory for policy override files |

### Enforcement Modes

- **STRICT** (default): Block denied access, block on errors. Recommended for production.
- **PERMISSIVE**: Block denied access, allow on errors. Useful for migration.
- **AUDIT**: Log only, never block. Useful for policy development.

## Instrumented Classes (Read Operations)

### java.nio.file.Files

The primary NIO filesystem API. All read operations are instrumented:

- `newInputStream(Path)`
- `newBufferedReader(Path)`
- `readAllBytes(Path)`
- `readAllLines(Path)`
- `readString(Path)`
- `lines(Path)`
- `list(Path)`
- `walk(Path)`
- `find(Path, ...)`

### java.io.FileInputStream

The legacy IO API. Both constructors are instrumented:

- `FileInputStream(File)`
- `FileInputStream(String)`

### java.io.RandomAccessFile

Direct file access API. Both constructors are instrumented:

- `RandomAccessFile(File, String)`
- `RandomAccessFile(String, String)`

### java.io.FileReader

Character stream API. Both constructors are instrumented:

- `FileReader(File)`
- `FileReader(String)`

### java.nio.channels.FileChannel

NIO channel API. The factory method is instrumented:

- `FileChannel.open(Path, ...)`

## Instrumented Classes (Write Operations)

### java.nio.file.Files

All write operations are instrumented:

- `newOutputStream(Path)`
- `newBufferedWriter(Path)`
- `write(Path, byte[])`
- `write(Path, Iterable)`
- `writeString(Path, CharSequence)`
- `copy(InputStream, Path)`
- `copy(Path, OutputStream)`
- `move(Path, Path)`
- `createFile(Path)`
- `createDirectory(Path)`
- `createDirectories(Path)`
- `delete(Path)`
- `deleteIfExists(Path)`

### java.io.FileOutputStream

The legacy IO write API. Both constructors are instrumented:

- `FileOutputStream(File)`
- `FileOutputStream(String)`

### java.io.FileWriter

Character stream write API. Both constructors are instrumented:

- `FileWriter(File)`
- `FileWriter(String)`

## Instrumented Classes (Network Outbound)

### java.net.Socket

Client socket connections are instrumented:

- `Socket(String, int)`
- `Socket(InetAddress, int)`
- `Socket.connect(SocketAddress)`

### java.nio.channels.SocketChannel

NIO socket connections are instrumented:

- `SocketChannel.connect(SocketAddress)`

## Instrumented Classes (Network Listen)

### java.net.ServerSocket

Server socket binding is instrumented:

- `ServerSocket(int)`
- `ServerSocket(int, int)`
- `ServerSocket.bind(SocketAddress)`

### java.nio.channels.ServerSocketChannel

NIO server socket binding is instrumented:

- `ServerSocketChannel.bind(SocketAddress)`

## Instrumented Classes (Thread Creation)

### java.lang.Thread

Thread creation is instrumented:

- `Thread.start()`

## Instrumented Classes (Native Library Loading)

### java.lang.System

Native library loading is instrumented:

- `System.loadLibrary(String)`
- `System.load(String)`

### java.lang.Runtime

Runtime native loading is instrumented:

- `Runtime.loadLibrary(String)`
- `Runtime.load(String)`

## Instrumented Classes (Environment Variables)

### java.lang.System

Environment variable access is instrumented:

- `System.getenv()` — bulk read (requires no-arg or `*` entitlement)
- `System.getenv(String)` — single variable read

## Instrumented Classes (System Properties)

### java.lang.System

System property access is instrumented:

- `System.getProperty(String)` — single property read
- `System.getProperty(String, String)` — single property read with default
- `System.getProperties()` — bulk read (requires no-arg or `*` entitlement)
- `System.setProperty(String, String)` — single property write
- `System.setProperties(Properties)` — bulk write (requires no-arg or `*` entitlement)
- `System.clearProperty(String)` — single property removal (write)

## Limitations

### Current Scope

The following capabilities are fully enforced:

- `fs.read(root, glob)` — filesystem read operations
- `fs.write(root, glob)` — filesystem write operations
- `fs.hardlink(root, glob)` — hard link creation (v0.3+)
- `network.outbound(hostPattern?, portSpec?)` — outbound socket connections with optional host/port filtering
- `network.listen(portSpec?)` — server socket binding with optional port or port range
- `threads.create` — thread creation
- `native.load(pattern?)` — native library loading
- `env.read(pattern?)` — environment variable read access
- `system.property.read(pattern?)` — system property read access
- `system.property.write(pattern?)` — system property write access
- `process.exec(pattern?)` — process execution (v0.3+)
- `crypto.provider` — JCE crypto provider modification (v0.3+)

### Trusted Modules (v0.3+)

Modules can be marked as "trusted" in external policy overrides to bypass all capability checks.
This is intended for native libraries like PyTorch that require unrestricted access.
Requires `-Djguard.allow.trusted=true` system property.

**Host patterns** for `network.outbound`:
- `*` matches exactly one DNS segment (e.g., `*.example.com` matches `api.example.com`)
- `**` matches one or more DNS segments (e.g., `**.example.com` matches `a.b.c.example.com`)

**Port specs** can be integers (`443`) or ranges (`"8080-8090"`).

**Target patterns** for `env.read`, `system.property.read/write`, `native.load`:
- No argument or `*` — matches any target (also grants bulk API access)
- `HOME` — exact match for specific target
- `app.**` — matches `app` and all descendants (e.g., `app.config.setting`)
- `app.*` — matches direct children only (e.g., `app.config` but not `app.config.setting`)

**Bulk API gating**: Methods like `System.getenv()`, `System.getProperties()`, and `System.setProperties()` require no-arg or `*` entitlement. Specific patterns do not grant bulk access.

### JVM Bootstrap Operations

Operations during JVM bootstrap (module loading, class loading) are allowed regardless of policy. This is necessary because the application caller cannot be determined during bootstrap.

## Building

```bash
./gradlew :agent:shadowJar
```

The shadow JAR includes all dependencies and is suitable for use as a Java agent. ByteBuddy and ASM are relocated to avoid conflicts with application dependencies.

## Running the Demo

```bash
cd samples/sandbox-demo

# Without agent (all operations succeed)
../../gradlew run

# With agent (unentitled operations blocked)
../../gradlew runWithAgent
```

## Policy Hot Reload

Enable hot reload to update entitlements without restarting the JVM:

```bash
java -javaagent:jguard-agent.jar=/etc/myapp/policy.bin \
     -Djguard.reload=true \
     -Djguard.reload.interval=5 \
     -jar myapp.jar
```

When enabled, the agent polls the policy file for changes. When a change is detected:

1. New policy is loaded from disk
2. PolicyEnforcer is atomically swapped
3. Decision cache is cleared
4. Subsequent operations use new entitlements

This enables zero-downtime policy updates in production environments.

## Multi-Module Discovery

For applications with multiple JPMS modules, jGuard **automatically discovers** policies embedded in signed JARs. No configuration needed:

```bash
# Just attach the agent - discovery is automatic!
java -javaagent:jguard-agent.jar -jar myapp.jar
```

### How It Works

1. Agent scans the classpath/module path for JARs containing `META-INF/jguard/policy.bin`
2. Only signed JARs are accepted by default (prevents malicious policy injection)
3. Each module's policy is indexed by module name
4. Enforcement uses caller module identity from stack walking

### Single-Module Mode

To use an explicit policy file (disables auto-discovery):

```bash
java -javaagent:jguard-agent.jar=/path/to/policy.bin -jar myapp.jar
```

### Development Mode

For local development with unsigned JARs:

```bash
java -javaagent:jguard-agent.jar \
     -Djguard.allowUnsignedPolicies=true \
     -jar myapp.jar
```

**Warning**: Never use `allowUnsignedPolicies=true` in production!

### Module Isolation

Each module can only use its own entitlements. Module A cannot use Module B's entitlements, even if they're in the same application.

## External Policies (Grant/Deny)

External policies allow administrators to modify entitlements at deployment time without rebuilding applications. External policies can both **grant** and **deny** capabilities.

### Configuration

```bash
java -javaagent:jguard-agent.jar \
     -Djguard.policy.override=/etc/myapp/policies \
     -jar myapp.jar
```

### External Policy Directory Structure

```
/etc/myapp/policies/
├── _global.bin                 # Applies to ALL modules
├── com.example.core.bin        # Policy for com.example.core module
├── com.example.net.bin         # Policy for com.example.net module
└── org.locationtech.proj4j.bin # Policy for non-JPMS library (by package prefix)
```

### Grant/Deny Syntax

```text
security module com.example.app {
    // Grant: adds to effective permissions (union)
    entitle com.example.app.reports.. to fs.write("/var/reports", "**");

    // Deny: removes from effective permissions (set difference)
    deny com.example.app.. to network.outbound;

    // Deny (defensive): suppress warning if capability not already granted
    deny(defensive) com.example.app.. to native.load;
}
```

### Merge Behavior

```
effective = (embedded ∪ external_grants ∪ global_grants) - (external_denials ∪ global_denials)
```

| Scenario | Result |
|----------|--------|
| External grants new capability | Added to effective permissions |
| External denies existing capability | Removed from effective permissions |
| External grants AND denies same capability | Denial wins |
| No external policy for module | Embedded policy applies unchanged |

### Use Cases

| Scenario | Solution |
|----------|----------|
| Non-JPMS library needs permissions | External policy grants capabilities |
| JPMS library without jGuard | External policy grants capabilities |
| Upstream library is overly permissive | External policy denies capabilities |
| Developer forgot a permission | External policy adds missing grant |
| Airgapped environment | Global policy denies network access |

### Example: Airgapped Environment

```text
// /etc/myapp/policies/_global.bin
security module _global {
    deny module to network.outbound;
    deny module to network.listen;
    deny(defensive) module to native.load;
}
```

### Example: Restrict Overly Permissive Library

```text
// /etc/myapp/policies/com.overly.permissive.bin
security module com.overly.permissive {
    // Library grants network.outbound to entire module - we restrict it
    deny module to network.outbound;
    entitle com.overly.permissive.http.. to network.outbound;
}
```

### Warning Messages

**Redundant deny warning:**
```
[WARN] [jguard] Redundant deny: com.example.foo.. -> threads.create (not in granted set)
```
Suppress with `deny(defensive)` for intentional defensive denials.

**Unknown module warning:**
```
[WARN] [jguard] External policy 'com.example.typo' does not match any loaded module
```
This helps catch typos in policy filenames.

### Hot Reload

External policy files are included in hot reload. Update a policy file and changes take effect within the reload interval. This enables zero-downtime policy updates:

- Adding forgotten grants
- Adding new denials
- Modifying existing policies
- Adding policies for new modules

## Production Deployment

The agent is designed for production use with:

- **Robust Bootstrap Injection**: Uses `appendToBootstrapClassLoaderSearch()` with a properly packaged bootstrap JAR
- **Built-in Logging**: Simple console logger with no external dependencies
- **Graceful Error Handling**: Configurable behavior for errors and edge cases
- **Shadow JAR Isolation**: ByteBuddy and ASM are relocated to avoid classpath conflicts
- **Policy Hot Reload**: Update entitlements without JVM restart
