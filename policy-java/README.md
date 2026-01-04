# jGuard Policy Java API

A type-safe, fluent Java API for defining jGuard security policies. This module provides an alternative to the `.jguard` DSL for developers who prefer defining policies in Java code.

## When to Use This API

Use the Java API when you need:

- **Programmatic policy generation** - Build policies dynamically based on configuration
- **IDE support** - Autocompletion, refactoring, and compile-time type checking
- **Java toolchain integration** - Policies as part of your build process
- **Testing** - Programmatically create policies for unit tests

For static policies, the `.jguard` DSL may be more readable. Both produce identical output.

## Quick Start

```java
import static org.jguard.policy.java.Capabilities.*;
import static org.jguard.policy.java.Subjects.*;

PolicyDescriptor policy = JGuardPolicy.forModule("com.example.app")
    .grant(module(), fsRead("/data", "*.json"))
    .grant(pkg("com.example.app.net"), networkOutbound())
    .grant(pkgRecursive("com.example.app.worker"), threadsCreate())
    .build();
```

This is equivalent to:

```java
// module-info.jguard
security module com.example.app {
    entitle module to fs.read("/data", "*.json");
    entitle com.example.app.net to network.outbound;
    entitle com.example.app.worker.. to threads.create;
}
```

## API Reference

### JGuardPolicy

The main builder class for creating policies.

```java
// Create a new policy for a module
JGuardPolicy.forModule("com.example.app")
    .grant(subject, capability)  // Add entitlements
    .grant(subject, capability)
    .build();                    // Build immutable PolicyDescriptor
```

### Subjects

Factory methods for defining who receives a capability.

| Method | Equivalent DSL | Description |
|--------|---------------|-------------|
| `module()` | `module` | Entire module (all packages) |
| `pkg("com.example")` | `com.example` | Exact package match |
| `pkgChildren("com.example")` | `com.example.*` | Direct child packages only |
| `pkgRecursive("com.example")` | `com.example..` | Package and all descendants |

### Capabilities

Factory methods for defining what actions are permitted.

| Method | Equivalent DSL | Description |
|--------|---------------|-------------|
| `fsRead(root, glob)` | `fs.read("/path", "*.ext")` | Read files matching glob under root |
| `fsWrite(root, glob)` | `fs.write("/path", "*.ext")` | Write files matching glob under root |
| `networkOutbound()` | `network.outbound` | Make outbound network connections |
| `networkListen(port)` | `network.listen(8080)` | Listen on a specific port |
| `threadsCreate()` | `threads.create` | Create new threads |
| `nativeLoad()` | `native.load` | Load native libraries |

## Examples

### Filesystem Access

```java
// Read JSON files from /data directory
grant(module(), fsRead("/data", "*.json"));

// Write logs to /tmp
grant(module(), fsWrite("/tmp", "*.log"));

// Read any file recursively under /config
grant(module(), fsRead("/config", "**/*"));
```

### Network Access

```java
// Allow outbound connections from network package
grant(pkg("com.example.app.http"), networkOutbound());

// Allow listening on port 8080 for server packages
grant(pkgChildren("com.example.app.server"), networkListen(8080));
```

### Thread Management

```java
// Allow worker packages to spawn threads
grant(pkgRecursive("com.example.app.worker"), threadsCreate());
```

### Native Libraries

```java
// Allow JNI package to load native libraries
grant(pkg("com.example.app.jni"), nativeLoad());
```

### Complete Example

```java
import static org.jguard.policy.java.Capabilities.*;
import static org.jguard.policy.java.Subjects.*;

import org.jguard.policy.java.JGuardPolicy;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.serialization.BinaryPolicyWriter;
import org.jguard.policy.serialization.JsonPolicyWriter;

public class PolicyGenerator {

    public static void main(String[] args) throws Exception {
        PolicyDescriptor policy = JGuardPolicy.forModule("com.example.app")
            // Module-wide filesystem access
            .grant(module(), fsRead("/data", "*.json"))
            .grant(module(), fsWrite("/tmp", "*.log"))

            // Network access for specific packages
            .grant(pkg("com.example.app.http"), networkOutbound())
            .grant(pkgChildren("com.example.app.server"), networkListen(8080))

            // Thread spawning for worker hierarchy
            .grant(pkgRecursive("com.example.app.worker"), threadsCreate())

            // Native library loading
            .grant(pkg("com.example.app.jni"), nativeLoad())

            .build();

        // Write binary output
        byte[] binary = BinaryPolicyWriter.toBytes(policy);
        Files.write(Path.of("policy.bin"), binary);

        // Write JSON output (for debugging)
        String json = JsonPolicyWriter.toJson(policy);
        Files.writeString(Path.of("policy.json"), json);
    }
}
```

## Parity with .jguard Files

Policies built with this Java API produce **byte-identical** output to equivalent `.jguard` files. This guarantee is verified by comprehensive parity tests.

```java
// These two produce identical binary/JSON output:

// Java API
PolicyDescriptor javaPolicy = JGuardPolicy.forModule("com.example.app")
    .grant(module(), networkOutbound())
    .build();

// .jguard file
// security module com.example.app {
//     entitle module to network.outbound;
// }
```

## Validation

The Java API performs validation at construction time:

- **Null checks** - All arguments are validated for null
- **Port ranges** - `networkListen()` validates port is 0-65535
- **Package names** - Invalid package name syntax is rejected

```java
// These throw IllegalArgumentException:
fsRead(null, "*.json");           // null root
networkListen(-1);                // invalid port
pkg("");                          // empty package name
pkg(".com.example");              // invalid syntax
```

## Determinism

Built policies are automatically normalized:

- **Sorted** - Entitlements are sorted (module first, then packages alphabetically)
- **Deduplicated** - Duplicate entitlements are removed
- **Immutable** - The returned `PolicyDescriptor` cannot be modified

```java
// Order doesn't matter - output is always sorted
JGuardPolicy.forModule("com.example.app")
    .grant(pkg("z.pkg"), networkOutbound())
    .grant(module(), networkOutbound())      // Will appear first in output
    .grant(pkg("a.pkg"), networkOutbound())  // Will appear before z.pkg
    .build();
```

## Dependency

```groovy
dependencies {
    implementation("org.jguard:jguard-policy-java:0.1.0")
}
```

## License

Apache-2.0
