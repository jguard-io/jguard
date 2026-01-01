# jGuard Sandbox Demo

This sample demonstrates how to integrate jGuard into a Java application.

## What is jGuard?

jGuard is a capability-based security framework for JDK 21+. It lets you declare exactly what your module is allowed to do—filesystem access, network connections, thread creation—and enforces those limits at runtime.

## Getting Started

### 1. Add the Gradle Plugin

```groovy
plugins {
    id "java"
    id "org.jguard.policy" version "0.1.0"
}

dependencies {
    implementation "org.jguard:core:0.1.0"
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
    entitle com.example.myapp.workers.. to threads.spawn;

}
```

The policy file declares:
- **What** capabilities are granted (`fs.read`, `network.outbound`, `threads.spawn`)
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
| `network.outbound` | Make outbound network connections |
| `network.listen(port)` | Listen on a port |
| `threads.spawn` | Create threads |
| `native.load` | Load native libraries |

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
    │       ├── Main.java
    │       ├── net/NetworkClient.java
    │       └── worker/BackgroundWorker.java
    └── test/java/
        └── org/jguard/samples/sandbox/
            └── EntitlementTest.java
```

## License

Apache-2.0
