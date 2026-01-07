# jGuard Sandbox Demo

This sample demonstrates how to integrate jGuard into a Java application.

## What is jGuard?

jGuard is a capability-based security framework for JDK 21+. It lets you declare exactly what your module is allowed to do—filesystem access, network connections, thread creation—and enforces those limits at runtime.

## Getting Started

### 1. Add the Gradle Plugin

```groovy
plugins {
    id "java"
    id "io.jguard.policy" version "0.1.0"
}

dependencies {
    implementation "io.jguard:core:0.1.0"
}
```

That's it for build configuration.

### 2. Write Your Policy

Create `src/main/java/module-info.jguard` alongside your `module-info.java`:

```
security module com.example.myapp {

    // Grant filesystem read access to config directory
    entitle module to fs.read("/etc/myapp", "**/*");

    // Grant network access to specific packages
    entitle com.example.myapp.http to network.outbound;

    // Grant thread spawning to worker packages
    entitle com.example.myapp.workers.. to threads.create;

}
```

The policy file declares:
- **What** capabilities are granted (`fs.read`, `network.outbound`, `threads.create`)
- **Who** gets them (`module` for everything, or specific packages)

### 3. Write Your Java Code

Here's the key point: **your Java code doesn't change**.

```java
package com.example.myapp.http;

import java.net.http.HttpClient;

public class ApiClient {
    private final HttpClient client = HttpClient.newHttpClient();

    // This works because com.example.myapp.http is entitled to network.outbound
    public String fetch(String url) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(url)).build();
        return client.send(request, BodyHandlers.ofString()).body();
    }
}
```

No annotations. No special APIs. No try-catch for security exceptions in normal flow.

jGuard enforces your policy transparently—if the code is entitled, it runs; if not, it fails fast with a clear error.

## Policy Syntax

### Subjects

| Pattern | Meaning |
|---------|---------|
| `module` | The entire module |
| `com.example.pkg` | Exactly that package |
| `com.example.pkg.*` | Direct subpackages only |
| `com.example.pkg..` | Package and all descendants |

### Capabilities

| Capability | Description |
|------------|-------------|
| `fs.read(root, glob)` | Read files matching glob under root |
| `fs.write(root, glob)` | Write files matching glob under root |
| `network.outbound(host?, port?)` | Make outbound connections (optional host pattern and port/range) |
| `network.listen(port?)` | Listen on a port (optional port or range like `"8080-8090"`) |
| `threads.create` | Create threads |
| `native.load(pattern?)` | Load native libraries (optional pattern) |
| `env.read(pattern?)` | Read environment variables (optional pattern) |
| `system.property.read(pattern?)` | Read system properties (optional pattern) |
| `system.property.write(pattern?)` | Write system properties (optional pattern) |

Host patterns: `*` matches one DNS segment, `**` matches one or more. Example: `*.example.com`

Target patterns for `env.read`, `system.property.*`, `native.load`:
- No arg or `*` — any target (also grants bulk API access)
- `HOME` — exact match
- `app.**` — matches `app` and all descendants

### Host/Port Filtering Example

The demo includes a `RestrictedNetworkClient` that demonstrates host/port filtering:

```
// Policy restricts this package to specific hosts and ports
entitle io.jguard.samples.sandbox.net.restricted to network.outbound("*.example.com", "80-443");
```

When running with the agent:
- `api.example.com:443` → **ALLOWED** (host matches `*.example.com`, port in range)
- `evil.com:443` → **DENIED** (host doesn't match pattern)
- `api.example.com:8080` → **DENIED** (port outside range 80-443)

**Try it:**

```bash
# Without agent (all connections allowed)
../../gradlew run

# With agent (host/port filtering enforced)
../../gradlew runWithAgent
```

You'll see output like:

```
[ENTITLED] network.outbound("*.example.com", "80-443")
  Attempting to connect to api.example.com:443...
  SUCCESS: Connection ALLOWED (host matches *.example.com, port in 80-443)

[NOT ENTITLED] network.outbound to non-matching host
  Attempting to connect to evil.com:443...
  (Policy only allows *.example.com)
  BLOCKED (expected): Host 'evil.com' doesn't match '*.example.com'

[NOT ENTITLED] network.outbound to non-matching port
  Attempting to connect to api.example.com:8080...
  (Policy only allows ports 80-443)
  BLOCKED (expected): Port 8080 not in range 80-443
```

## What Gets Built

When you run `./gradlew build`, the plugin:

1. Compiles `module-info.jguard` → `policy.bin` (and optionally `policy.json`)
2. Packages them into your JAR at `META-INF/jguard/`

```
myapp.jar
├── module-info.class
├── com/example/myapp/...
└── META-INF/
    └── jguard/
        ├── policy.bin
        └── policy.json
```

## Running with Enforcement

To enable runtime enforcement, run with the jGuard agent:

```bash
java -javaagent:jguard-agent.jar -jar myapp.jar
```

Without the agent, your app runs normally (no enforcement). With the agent, policy violations fail immediately with clear diagnostics:

```
SecurityException: Capability denied
  Module: com.example.myapp
  Package: com.example.myapp.cli
  Attempted: network.outbound
  Reason: not entitled (only com.example.myapp.http is entitled to network.outbound)
```

## FAQ

### Do I need to change my existing code?

No. jGuard is purely additive:
- Add the plugin to `build.gradle`
- Add `module-info.jguard` next to `module-info.java`
- Add `jguard:core` as a dependency
- Run with the agent for enforcement

Your Java code stays exactly the same.

### What if I don't have a module-info.java?

jGuard requires JPMS modules. If you're not using modules yet, you'll need to add a `module-info.java` first. This is a one-time migration that also improves encapsulation.

### What happens if I forget to entitle something?

Without the agent: nothing, your code runs normally.

With the agent: you get a clear error telling you exactly what capability was missing and where. Add it to your policy and rebuild.

### Can I test without the agent?

Yes. Your tests run normally. You can also write tests that verify policy violations once enforcement is enabled (see `EntitlementTest.java` in this sample).

## Project Structure

```
sandbox-demo/
├── build.gradle
└── src/
    ├── main/java/
    │   ├── module-info.java          # JPMS module descriptor
    │   ├── module-info.jguard        # jGuard policy (lives next to module-info.java)
    │   └── org/jguard/samples/sandbox/
    │       ├── Main.java             # Demo runner
    │       ├── net/
    │       │   ├── NetworkClient.java             # Entitled to network.outbound (any host)
    │       │   └── restricted/
    │       │       └── RestrictedNetworkClient.java # Entitled to *.example.com:80-443 only
    │       ├── worker/BackgroundWorker.java       # Entitled to threads.create
    │       ├── nativelib/NativeLoader.java        # Entitled to native.load
    │       └── config/ConfigReader.java           # Entitled to env.read, system.property.write("app.**")
    └── test/java/
        └── org/jguard/samples/sandbox/
            └── EntitlementTest.java
```

## License

Apache-2.0
