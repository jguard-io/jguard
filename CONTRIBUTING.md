# Contributing to jGuard

This guide explains how to contribute to jGuard, with a focus on adding new capabilities.

## Architecture Overview

jGuard uses a two-module architecture for proper classloader handling:

```
ByteBuddy Advice (interceptors)
       │
       ▼
BootstrapEnforcer.dispatch(Operation, arg0, arg1)  ← bootstrap classloader
       │
       ▼ (single callback)
EnforcementCallback.check(CallerContext, Operation, arg0, arg1)  ← agent classloader
       │
       ▼
PolicyEnforcer.check()  ← category-based dispatch
```

### Modules

| Module | Purpose | Classloader |
|--------|---------|-------------|
| `agent-bootstrap` | Classes injected into bootstrap classloader | Bootstrap |
| `agent` | ByteBuddy instrumentation and policy enforcement | System/App |
| `policy` | Policy model and compilation | System/App |
| `core` | Public API for applications | System/App |

### Key Classes

| Class | Location | Purpose |
|-------|----------|---------|
| `Operation` | agent-bootstrap | Enum with capability name and category |
| `Operation.Category` | agent-bootstrap | Determines matching logic (SIMPLE, PORT, etc.) |
| `BootstrapEnforcer` | agent-bootstrap | Entry points called by advice |
| `JGuardAgent` | agent | Agent entry point (injects bootstrap, delegates to AgentInitializer) |
| `AgentInitializer` | agent | Agent initialization (policy loading, instrumentation wiring) |
| `PolicyEnforcer` | agent | Category-based policy evaluation |
| `*Interceptor` | agent | ByteBuddy advice classes |

## Categories

Categories determine how capabilities match against policy. **Using an existing category means zero changes to PolicyEnforcer.**

| Category | Policy Args | Matching Logic | Examples |
|----------|-------------|----------------|----------|
| `SIMPLE` | None | Subject match only | `threads.create` |
| `PORT` | Optional `(port)` or `("start-end")` | No args = any port, with arg = specific port or range | `network.listen` |
| `HOST_PORT` | Optional `(hostPattern?, portSpec?)` | Host glob + port/range filtering | `network.outbound` |
| `TARGET_PATTERN` | Optional `(pattern)` | No args = any target, with arg = pattern match | `native.load`, `env.read`, `system.property.*` |
| `FILESYSTEM` | Required `(root, glob)` | Path must match root + glob | `fs.read`, `fs.write` |

## Adding a New Capability

### If Using an Existing Category (Easiest)

For capabilities like `threads.create` that use the `SIMPLE` category:

**Only 4 changes needed, 0 lines in PolicyEnforcer!**

#### Step 1: Add to Operation Enum (1 line)

**File:** `agent-bootstrap/src/main/java/io/jguard/bootstrap/Operation.java`

```java
public enum Operation {
  FS_READ("fs.read", Category.FILESYSTEM),
  FS_WRITE("fs.write", Category.FILESYSTEM),
  NET_CONNECT("network.outbound", Category.HOST_PORT),
  NET_LISTEN("network.listen", Category.PORT),
  THREAD_CREATE("threads.create", Category.SIMPLE);  // ← Add this line
  ...
}
```

#### Step 2: Add Entry Point in BootstrapEnforcer (~5 lines)

**File:** `agent-bootstrap/src/main/java/io/jguard/bootstrap/BootstrapEnforcer.java`

```java
/**
 * Called by ByteBuddy advice when a thread is being started.
 */
public static void onThreadCreate(Thread thread) {
  dispatch(Operation.THREAD_CREATE, thread != null ? thread.getName() : "unnamed", 0);
}
```

#### Step 3: Create Interceptor Advice (~20 lines)

**File:** `agent/src/main/java/io/jguard/agent/ThreadInterceptor.java`

```java
public final class ThreadInterceptor {

  private ThreadInterceptor() {}

  public static class ThreadStartAdvice {

    private ThreadStartAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.This Thread thread) {
      BootstrapEnforcer.onThreadCreate(thread);
    }
  }
}
```

#### Step 4: Wire Advice in AgentInitializer (~5 lines)

**File:** `agent/src/main/java/io/jguard/agent/AgentInitializer.java`

```java
// Thread.start() instrumentation
.type(named("java.lang.Thread"))
.transform((builder, typeDescription, classLoader, module, protectionDomain) ->
    builder.visit(
        Advice.to(ThreadInterceptor.ThreadStartAdvice.class)
            .on(named("start").and(takesNoArguments()))))
```

**That's it!** PolicyEnforcer's category-based dispatch handles `SIMPLE` capabilities automatically.

### If Adding a New Category

If your capability needs different matching logic, add a new category:

#### Step 1: Add Category to Operation.Category enum

```java
public enum Category {
  FILESYSTEM,
  SIMPLE,
  PORT,
  HOST_PORT,
  TARGET_PATTERN,
  MY_NEW_CATEGORY  // ← Add here
}
```

#### Step 2: Update BootstrapEnforcer helpers

Add cases to `formatArgs()` and `validateArgs()`:

```java
private static String formatArgs(Operation op, Object arg0, int arg1) {
  return switch (op.category()) {
    case FILESYSTEM -> String.valueOf(arg0);
    case SIMPLE -> arg0 != null ? arg0 + ":" + arg1 : "n/a";
    case PORT -> "port=" + arg1;
    case HOST_PORT -> arg0 + ":" + arg1;
    case TARGET_PATTERN -> arg0 != null ? String.valueOf(arg0) : "any";
    case MY_NEW_CATEGORY -> /* your format */;
  };
}
```

#### Step 3: Update PolicyEnforcer category handlers

Add cases to `formatDetails()`, `buildCacheKey()`, and `isAllowed()`:

```java
private boolean isAllowed(String callerPackage, Operation op, Object arg0, int arg1) {
  String capability = op.capabilityName();
  return switch (op.category()) {
    case FILESYSTEM -> isAllowedFilesystem(callerPackage, (Path) arg0, capability);
    case SIMPLE -> isAllowedSimple(callerPackage, capability);
    case PORT -> isAllowedPort(callerPackage, arg1, capability);
    case HOST_PORT -> isAllowedHostPort(callerPackage, (String) arg0, arg1, capability);
    case TARGET_PATTERN -> isAllowedTargetPattern(callerPackage, (String) arg0, capability);
    case MY_NEW_CATEGORY -> isAllowedMyCategory(callerPackage, arg0, arg1, capability);
  };
}
```

Then implement `isAllowedMyCategory()` with your matching logic.

This is a one-time cost (~30 lines) that enables all future capabilities in that category.

## Testing

### Unit Tests

Add tests in `agent/src/test/java/io/jguard/agent/PolicyEnforcerTest.java`:

```java
@Nested
@DisplayName("Thread create entitlements")
class ThreadCreateTest {

  @Test
  @DisplayName("allows thread creation when entitled")
  void allowsWhenEntitled() {
    Entitlement entitlement = new Entitlement(
        SubjectPattern.module(),
        CapabilityGrant.of("threads.create"));
    PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));
    PolicyEnforcer enforcer = createEnforcer(policy);

    assertThat(enforcer.check(caller("com.example.app"), Operation.THREAD_CREATE, "worker", 0))
        .isNull();
  }
}
```

### Integration Tests

Add a test case in `samples/sandbox-demo` that exercises the new capability with the agent.

## Capability Design Guidelines

1. **Choose the right category** - Use existing categories when possible
2. **Minimal arguments** - Only include arguments needed for policy decisions
3. **Consistent naming** - Follow existing patterns (`category.action`)
4. **Clear semantics** - Document what the capability controls

## Argument Conventions by Category

| Category | arg0 | arg1 |
|----------|------|------|
| FILESYSTEM | `Path` | `0` (unused) |
| SIMPLE | `String` description (for logging) | `0` (unused) |
| PORT | `null` | `int` port |
| HOST_PORT | `String` host | `int` port |
| TARGET_PATTERN | `String` target (class name, etc.) | `0` (unused) |

## Common Pitfalls

### Advice Classes

- **Only reference bootstrap classes** - Advice is woven into JDK classes which can only see the bootstrap classloader
- **No instance state** - Advice classes must be stateless with static methods
- **Handle nulls** - Arguments may be null; check before calling BootstrapEnforcer

### BootstrapEnforcer

- **No external dependencies** - Bootstrap module must only use JDK classes
- **Normalize in entry points** - Convert File→Path, InetSocketAddress→host+port before dispatch

### PolicyEnforcer

- **Category switches are exhaustive** - Missing cases cause compile errors
- **Cache key uniqueness** - Include all relevant arguments in cache key

## Building and Testing

```bash
# Build all modules
./gradlew build

# Run sandbox-demo without agent (no enforcement)
cd samples/sandbox-demo && ../../gradlew run

# Run sandbox-demo with agent (enforcement enabled)
cd samples/sandbox-demo && ../../gradlew runWithAgent

# Run with different modes
../../gradlew runWithAgent -Pjguard.mode=audit
../../gradlew runWithAgent -Pjguard.mode=permissive
```

## Releasing (Maintainers Only)

This section is for release managers with write access to Maven Central and Gradle Plugin Portal.

### Prerequisites

1. **Sonatype Central Portal access** - Must be a verified publisher for `io.jguard` namespace
2. **Gradle Plugin Portal access** - Must have API keys for the jGuard plugin
3. **GPG signing key** - Must have the jGuard release signing key

### One-Time Setup

Copy the release environment template and fill in your credentials:

```bash
cp scripts/setup-release-env.template.sh ~/keys/jguard/setup-release-env.sh
chmod 600 ~/keys/jguard/setup-release-env.sh
# Edit the file and replace REPLACE_ME values with your credentials
```

Before each release, source the environment:

```bash
source ~/keys/jguard/setup-release-env.sh
```

### Release Process

1. **Update version** in `build.gradle`:
   ```groovy
   allprojects {
     version = "X.Y.Z"  // Remove -SNAPSHOT for release
   }
   ```

2. **Build and test**:
   ```bash
   ./gradlew clean build
   cd samples/sandbox-demo && ../../gradlew build
   ```

3. **Publish to Maven Central**:
   ```bash
   ./gradlew publishAllPublicationsToMavenCentralRepository
   ```

4. **Release on Central Portal**:
   - Go to https://central.sonatype.com/publishing
   - Verify artifacts are validated
   - Click **Publish** to release

5. **Publish Gradle plugin**:
   ```bash
   ./gradlew :gradle-plugin:publishPlugins
   ```

6. **Create GitHub release**:
   ```bash
   git tag v${VERSION}
   git push origin v${VERSION}
   ```
   Then create a release on GitHub with changelog.

7. **Bump to next snapshot**:
   ```groovy
   version = "X.Y.(Z+1)-SNAPSHOT"
   ```

### Published Artifacts

| Artifact | Destination |
|----------|-------------|
| `io.jguard:jguard-core` | Maven Central |
| `io.jguard:jguard-policy` | Maven Central |
| `io.jguard:jguard-policy-java` | Maven Central |
| `io.jguard:jguard-agent` | Maven Central |
| `io.jguard:jguard-agent-bootstrap` | Maven Central |
| `io.jguard:jguard-cli` | Maven Central |
| `io.jguard.policy` plugin | Gradle Plugin Portal |

## Questions?

Open an issue at https://github.com/jguard-io/jguard/issues
