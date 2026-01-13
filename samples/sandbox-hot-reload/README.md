# Hot Reload Demo

This demo showcases jGuard's **policy hot reload** feature with **signed JARs** and
**discovery mode**. This represents a production-like configuration where:
- JARs are signed for policy verification
- Policies are discovered from embedded JARs on the classpath
- External policies can be hot-reloaded without JVM restart

## The Feature

Hot reload enables live policy updates by:
1. Polling the external policy directory at configurable intervals
2. Detecting file modifications via timestamps
3. Re-merging external policies with cached base policies
4. Atomically swapping the policy enforcer when changes are detected

This is useful for:
- **Development**: Quickly iterate on policy definitions
- **Operations**: Adjust permissions without service restarts
- **Emergency response**: Rapidly restrict compromised modules

## Running the Demo

### Prerequisites

Build the jGuard project from the repository root:

```bash
cd ../..
./gradlew build
```

### Quick Start (Automated Demo)

Run the automated demo script that demonstrates hot reload end-to-end:

```bash
cd samples/sandbox-hot-reload
./demo.sh
```

The script tests three scenarios:

#### Scenario A: REMOVE an entitlement

- Removes `network.outbound` from the policy
- Recompiles and hot reload detects the change
- **Result**: Warning logged about removed capability, policy applied
- `network.outbound` changes from ALLOWED → BLOCKED

```
[WARN] PolicyReloader - Policy validation warnings (1 issue(s)):
[WARN] PolicyReloader -   - Module 'io.jguard.samples.hotreload': 1 capability(s) removed: [network.outbound]
[INFO] PolicyReloader - Policy reloaded successfully
```

#### Scenario B: ADD an invalid policy

- Adds an unknown capability `invalid.capability`
- Compilation FAILS (caught at compile-time, not runtime)
- **Result**: App continues running with the OLD policy (no crash!)
- The agent never sees invalid policies - they're rejected at compile-time

```
ERROR: Unknown capability: 'invalid.capability'
BUILD FAILED
```

#### Scenario C: ADD valid entitlements

- Adds `env.read` and `threads.create` to the policy
- Recompiles and hot reload detects the change
- **Result**: Policy applied successfully, new capabilities become ALLOWED

```
[INFO] PolicyMerger - Module 'io.jguard.samples.hotreload': 5 entitlements after merge (1 -> 5, delta +4)
[INFO] PolicyReloader - Policy reloaded successfully
```

This demonstrates the complete hot reload cycle without any manual intervention.

### Manual Demo (Interactive)

For hands-on exploration, you can run the demo manually:

#### Step 1: Start the Application

```bash
./gradlew :app:runDemo
```

This runs the application with:
- Signed JARs (for policy verification)
- Discovery mode (policies discovered from JARs)
- Hot reload enabled (2 second polling interval)

The application will:
- Test various operations every 5 seconds
- Display which operations are ALLOWED or BLOCKED
- Poll for policy changes every 2 seconds

#### Step 2: Modify Policies While Running

In a **separate terminal**, edit the external policy:

```bash
# Edit the policy file
vi app/policies-src/io.jguard.samples.hotreload.jguard
```

For example, comment out the `network.outbound` entitlement:

```diff
- entitle module to network.outbound;
+ // entitle module to network.outbound;
```

#### Step 3: Recompile the Policy

```bash
./gradlew :app:compileExternalPolicies
```

#### Step 4: Watch the Change Take Effect

Within 2 seconds, you'll see the output change:

**Before:**
```
  network.outbound ..... ALLOWED
```

**After:**
```
  network.outbound ..... BLOCKED - not entitled
```

No restart required!

## Configuration

### Gradle Configuration

This demo uses JAR signing with discovery mode:

```groovy
// Sign the JAR for policy verification
tasks.named("jar", Jar) {
  doLast {
    ant.signjar(
      jar: archiveFile.get().asFile,
      keystore: file("keystore/demo.keystore"),
      storepass: "changeit",
      alias: "demo"
    )
  }
}

jguardPolicy {
  // Discovery mode is the default - policies discovered from signed JARs

  // Enable hot reload
  hotReload = true
  hotReloadInterval = 2  // seconds (default: 5)

  // External policies directory (hot reloadable)
  externalPoliciesSourceDir = file("policies-src")
  externalPoliciesOutputDir = file("policies")
}
```

### System Properties (Advanced)

For manual JVM configuration:

| Property | Default | Description |
|----------|---------|-------------|
| `jguard.reload` | `false` | Enable hot reload |
| `jguard.reload.interval` | `5` | Poll interval in seconds |
| `jguard.policy.override` | - | External policies directory |

Example:
```bash
java -Djguard.reload=true \
     -Djguard.reload.interval=2 \
     -Djguard.policy.override=/path/to/policies \
     -javaagent:jguard-agent.jar \
     -jar myapp.jar
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        JVM Process                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Application │───▶│   jGuard     │───▶│   Policy     │   │
│  │     Code     │    │   Agent      │    │   Enforcer   │   │
│  └──────────────┘    └──────────────┘    └──────┬───────┘   │
│                                                 │           │
│                      ┌──────────────┐           │           │
│                      │   Policy     │◀──────────┘           │
│                      │   Reloader   │  (AtomicReference)    │
│                      └──────┬───────┘                       │
│                             │ polls                         │
└─────────────────────────────│───────────────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │  policies/*.bin  │  (on disk)
                    └──────────────────┘
```

### Discovery Mode + Hot Reload

In discovery mode with hot reload:

1. **Startup**: Agent scans signed JARs on classpath for embedded policies
2. **Cache**: Base policies are cached in memory (not reloaded)
3. **Watch**: PolicyReloader watches only the external override directory
4. **Reload**: When external policies change, they're re-merged with cached base
5. **Swap**: New PolicyEnforcer atomically replaces the old one

This design ensures:
- Base policies from JARs are immutable (security guarantee)
- Only external overrides can change at runtime
- Fast reload (no JAR scanning on every poll)

### Thread Safety

The reload uses `AtomicReference<PolicyEnforcer>` to ensure:
- No race conditions during swap
- In-flight permission checks complete with old policy
- New checks immediately use the new policy

### Error Handling

- **Missing file**: Logs warning, continues monitoring
- **Corrupted policy**: Logs error, keeps current enforcer
- **Syntax errors**: Caught at compile time (not runtime)

## Limitations

1. **Compile step required**: You must recompile `.jguard` → `.bin` after editing.
   The agent watches the compiled binary, not the source files.

2. **External policies only**: Hot reload watches the external override directory.
   Embedded policies (baked into JARs) cannot be hot-reloaded.

3. **Signed JARs required**: In production, JAR signing ensures policy integrity.
   This demo includes a self-signed keystore for demonstration.

## Generating a Keystore

This demo includes a pre-generated demo keystore. To create your own:

```bash
keytool -genkeypair \
  -alias mykey \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -keystore my.keystore \
  -storepass changeit \
  -dname "CN=Your Name, OU=Your Org, O=Your Company"
```

## Related Documentation

- [Agent Configuration](../../agent/README.md)
- [External Policies](../../docs/spec/jguard-policy-descriptor.md#6-external-policies)
- [Gradle Plugin](../../gradle-plugin/README.md)
