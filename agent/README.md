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
jguard compile src/main/java/module-info.jguard -o /etc/myapp/policy.bin

# 2. Run application with external policy
java -javaagent:jguard-agent.jar=/etc/myapp/policy.bin -jar myapp.jar

# 3. Update entitlements (requires restart, no rebuild)
jguard compile updated-policy.jguard -o /etc/myapp/policy.bin
systemctl restart myapp
```

This separation enables:
- **Security team** manages policy files independently
- **Dev team** ships application without embedded policies
- **Ops team** updates entitlements without rebuilding artifacts

### System Properties

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `jguard.policy` | path | (required) | Policy file location |
| `jguard.mode` | strict/permissive/audit | strict | Enforcement mode |
| `jguard.log.level` | error/warn/info/debug/trace | info | Log verbosity |
| `jguard.log.denied` | true/false | true | Log denied operations |
| `jguard.log.allowed` | true/false | false | Log allowed operations |
| `jguard.reload` | true/false | false | Enable policy hot reload |
| `jguard.reload.interval` | seconds | 5 | Hot reload poll interval |

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

## Limitations

### Current Scope

The following capabilities are fully enforced:

- `fs.read` — filesystem read operations
- `fs.write` — filesystem write operations
- `network.outbound` — outbound socket connections
- `network.listen` — server socket binding
- `threads.create` — thread creation
- `native.load` — native library loading

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

## Production Deployment

The agent is designed for production use with:

- **Robust Bootstrap Injection**: Uses `appendToBootstrapClassLoaderSearch()` with a properly packaged bootstrap JAR
- **Built-in Logging**: Simple console logger with no external dependencies
- **Graceful Error Handling**: Configurable behavior for errors and edge cases
- **Shadow JAR Isolation**: ByteBuddy and ASM are relocated to avoid classpath conflicts
- **Policy Hot Reload**: Update entitlements without JVM restart
