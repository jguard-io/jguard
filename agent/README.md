# jGuard Agent

The jGuard Java agent enforces capability-based security policies at runtime by instrumenting JDK classes.

## Quick Start

```bash
java -javaagent:jguard-agent.jar=/path/to/policy.bin -jar myapp.jar
```

## How It Works

The agent uses ByteBuddy to instrument `java.nio.file.Files` methods, intercepting file system operations and checking them against compiled policy files.

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

### System Properties

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `jguard.policy` | path | (required) | Policy file location |
| `jguard.mode` | strict/permissive/audit | strict | Enforcement mode |
| `jguard.log.level` | error/warn/info/debug/trace | info | Log verbosity |
| `jguard.log.denied` | true/false | true | Log denied operations |
| `jguard.log.allowed` | true/false | false | Log allowed operations |

### Enforcement Modes

- **STRICT** (default): Block denied access, block on errors. Recommended for production.
- **PERMISSIVE**: Block denied access, allow on errors. Useful for migration.
- **AUDIT**: Log only, never block. Useful for policy development.

## Instrumented Classes

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

## Limitations

### Current Scope (M3.1)

- Only `fs.read` capability is enforced
- Write operations are not yet instrumented

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

## Production Deployment

The agent is designed for production use with:

- **Robust Bootstrap Injection**: Uses `appendToBootstrapClassLoaderSearch()` with a properly packaged bootstrap JAR
- **Built-in Logging**: Simple console logger with no external dependencies
- **Graceful Error Handling**: Configurable behavior for errors and edge cases
- **Shadow JAR Isolation**: ByteBuddy and ASM are relocated to avoid classpath conflicts
