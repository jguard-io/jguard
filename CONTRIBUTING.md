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
| `PolicyEnforcer` | agent | Category-based policy evaluation |
| `*Interceptor` | agent | ByteBuddy advice classes |

## Categories

Categories determine how capabilities match against policy. **Using an existing category means zero changes to PolicyEnforcer.**

| Category | Policy Args | Matching Logic | Examples |
|----------|-------------|----------------|----------|
| `SIMPLE` | None | Subject match only | `network.outbound`, `threads.create` |
| `PORT` | Optional `(port)` | No args = any port, with arg = specific port | `network.listen` |
| `TARGET_PATTERN` | Optional `(pattern)` | No args = any target, with arg = pattern match | `reflect.invoke`, `native.load` |
| `FILESYSTEM` | Required `(root, glob)` | Path must match root + glob | `fs.read`, `fs.write` |

## Adding a New Capability

### If Using an Existing Category (Easiest)

For capabilities like `threads.create` that use the `SIMPLE` category:

**Only 4 changes needed, 0 lines in PolicyEnforcer!**

#### Step 1: Add to Operation Enum (1 line)

**File:** `agent-bootstrap/src/main/java/org/jguard/bootstrap/Operation.java`

```java
public enum Operation {
  FS_READ("fs.read", Category.FILESYSTEM),
  FS_WRITE("fs.write", Category.FILESYSTEM),
  NET_CONNECT("network.outbound", Category.SIMPLE),
  NET_LISTEN("network.listen", Category.PORT),
  THREAD_CREATE("threads.create", Category.SIMPLE);  // ← Add this line
  ...
}
```

#### Step 2: Add Entry Point in BootstrapEnforcer (~5 lines)

**File:** `agent-bootstrap/src/main/java/org/jguard/bootstrap/BootstrapEnforcer.java`

```java
/**
 * Called by ByteBuddy advice when a thread is being started.
 */
public static void onThreadCreate(Thread thread) {
  dispatch(Operation.THREAD_CREATE, thread != null ? thread.getName() : "unnamed", 0);
}
```

#### Step 3: Create Interceptor Advice (~20 lines)

**File:** `agent/src/main/java/org/jguard/agent/ThreadInterceptor.java`

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

#### Step 4: Wire Advice in JGuardAgent (~5 lines)

**File:** `agent/src/main/java/org/jguard/agent/JGuardAgent.java`

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
    case TARGET_PATTERN -> isAllowedTargetPattern(callerPackage, (String) arg0, capability);
    case MY_NEW_CATEGORY -> isAllowedMyCategory(callerPackage, arg0, arg1, capability);
  };
}
```

Then implement `isAllowedMyCategory()` with your matching logic.

This is a one-time cost (~30 lines) that enables all future capabilities in that category.

## Testing

### Unit Tests

Add tests in `agent/src/test/java/org/jguard/agent/PolicyEnforcerTest.java`:

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

## Questions?

Open an issue at https://github.com/lucenia/jguard/issues
