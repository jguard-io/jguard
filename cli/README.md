# jGuard CLI Tools

Command-line tools for working with jGuard policy descriptors.

## Installation

Build and install the distribution:

```bash
./gradlew :cli:installDist
```

The `jguard` binary will be available at:
```
cli/build/install/jguard/bin/jguard
```

## Commands

The `jguard` CLI provides several subcommands for policy management:

| Command | Description |
|---------|-------------|
| `compile` | Compile a `.jguard` source file to binary format |
| `inspect` | Inspect embedded policy in a JAR or policy file |
| `list` | List all policies found in JARs on a path |
| `diff` | Compare two policy files and show differences |
| `validate-override` | Validate that an override is a subset of embedded policy |

---

## jguard compile

Compiles `module-info.jguard` policy descriptors into binary format for runtime enforcement.

### Usage

```bash
jguard compile [OPTIONS] <source>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<source>` | Path to the `module-info.jguard` source file |

### Options

| Option | Description |
|--------|-------------|
| `-o, --output <path>` | **(Required)** Output path for the compiled binary policy file |
| `--json <path>` | Also output JSON format to the specified path |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Show help message and exit |

### Examples

**Basic compilation:**
```bash
jguard compile -o build/policy.bin src/main/java/module-info.jguard
```

**With JSON output for debugging:**
```bash
jguard compile -o build/policy.bin --json build/policy.json src/main/java/module-info.jguard
```

**Verbose mode:**
```bash
jguard compile -v -o build/policy.bin src/main/java/module-info.jguard
```

---

## jguard inspect

Inspects embedded policy in a JAR file or standalone policy binary.

### Usage

```bash
jguard inspect [OPTIONS] <path>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<path>` | Path to a JAR file or `.bin` policy file |

### Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed entitlement information |
| `-h, --help` | Show help message and exit |

### Examples

**Inspect a JAR:**
```bash
jguard inspect mymodule.jar
```

Output:
```
JAR: mymodule.jar
Policy: META-INF/jguard/policy.bin

Format version: 2
Modules: 1

  Module: com.example.mymodule
  Entitlements: 3
    - fs.read
    - network.outbound
    - threads.create
```

**Inspect with details:**
```bash
jguard inspect -v mymodule.jar
```

Output:
```
JAR: mymodule.jar
Policy: META-INF/jguard/policy.bin

Format version: 2
Modules: 1

  Module: com.example.mymodule
  Entitlements: 3
    - module -> fs.read("/data", "**")
    - module -> network.outbound("*.example.com", 443)
    - module -> threads.create
```

**Inspect policy with denials:**
```bash
jguard inspect -v external-policy.bin
```

Output:
```
Policy: external-policy.bin

Format version: 2
Modules: 1

  Module: com.example.app
  Entitlements: 2
    - module -> fs.read("/data", "**")
    - com.example.app.http.. -> network.outbound
  Denials: 2
    - module -> native.load (defensive)
    - com.example.app.. -> threads.create
```

**Inspect a standalone policy file:**
```bash
jguard inspect policy.bin
```

---

## jguard list

Lists all jGuard policies found in JARs within a directory. By default, only signed JARs are included.

### Usage

```bash
jguard list [OPTIONS] <directory>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<directory>` | Directory containing JAR files |

### Options

| Option | Description |
|--------|-------------|
| `--include-unsigned` | Include policies from unsigned JARs |
| `-v, --verbose` | Show entitlement counts per module |
| `-h, --help` | Show help message and exit |

### Examples

**List policies in libs directory:**
```bash
jguard list libs/
```

Output:
```
Module path: libs/
Policies found: 2
(signed JARs only; use --include-unsigned for all)

  com.example.core
    JAR: core-1.0.jar
    Signed: yes

  com.example.network
    JAR: network-1.0.jar
    Signed: yes
```

**Include unsigned JARs (for development):**
```bash
jguard list --include-unsigned libs/
```

**Verbose mode with entitlement counts:**
```bash
jguard list -v --include-unsigned libs/
```

---

## jguard diff

Compares two policy files and shows differences in entitlements.

### Usage

```bash
jguard diff <base> <compare>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<base>` | Path to first (base) policy file |
| `<compare>` | Path to second (comparison) policy file |

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |

### Examples

**Compare two policies:**
```bash
jguard diff embedded.bin override.bin
```

Output:
```
Module: com.example.app
  - module -> network.outbound("evil.com", 443)
  + module -> network.outbound("trusted.com", 443)
```

The output shows:
- `-` entries only in the first (base) file
- `+` entries only in the second (compare) file

**Identical policies:**
```bash
jguard diff policy1.bin policy2.bin
```

Output:
```
Policies are identical.
```

---

## jguard validate-override

Validates that an override policy is a valid subset of the embedded policy. Override policies can only **restrict** capabilities—they cannot grant new ones.

### Usage

```bash
jguard validate-override --override <path> (--jar <path> | --embedded <path>)
```

### Options

| Option | Description |
|--------|-------------|
| `--jar <path>` | Path to JAR containing the embedded policy |
| `--embedded <path>` | Path to embedded policy file (alternative to --jar) |
| `--override <path>` | **(Required)** Path to override policy file |
| `-h, --help` | Show help message and exit |

### Examples

**Validate against JAR:**
```bash
jguard validate-override --jar mymodule.jar --override /etc/myapp/overrides/mymodule.bin
```

**Validate against policy file:**
```bash
jguard validate-override --embedded embedded.bin --override override.bin
```

**Valid override output:**
```
Override is valid (all entitlements are subsets of embedded policy).
  Embedded modules: 1
  Override modules: 1
```

**Invalid override output:**
```
Error: Override for module 'com.example.app' contains 1 entitlement(s) not in embedded policy:
  - module -> network.outbound("evil.com", 443)

Override validation FAILED.
Overrides can only RESTRICT capabilities, not grant new ones.
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (validation failed, file not found, etc.) |
| 2 | Invalid command-line arguments |

---

## Error Output

Compilation errors are printed to stderr in gcc/clang style:

```
src/main/java/module-info.jguard:5:23: error: Unknown capability: 'bad.capability'
```

Format: `file:line:column: severity: message`

---

## Output Formats

### Binary Format (`.bin`)

Compact binary representation for runtime loading. Structure:

```
Header:
  magic:    4 bytes ("JGRD")
  version:  1 byte  (format version, currently 2)

Module count: varint

For each module:
  name:         length-prefixed UTF-8 string
  entitlements: count + repeated entitlement records
```

### JSON Format (`.json`)

Human-readable format for debugging and inspection:

```json
{
  "formatVersion": 2,
  "modules": [
    {
      "moduleName": "com.example.app",
      "entitlements": [
        {
          "subject": "module",
          "subjectType": "MODULE",
          "capability": "fs.read",
          "arguments": [
            {"type": "string", "value": "/data"},
            {"type": "string", "value": "*.json"}
          ]
        }
      ]
    }
  ]
}
```

---

## Supported Capabilities

The compiler validates that only known capabilities are used:

| Capability | Arguments | Description |
|------------|-----------|-------------|
| `fs.read` | `(root, glob)` | Read files matching glob under root |
| `fs.write` | `(root, glob)` | Write files matching glob under root |
| `network.outbound` | `(hostPattern?, portSpec?)` | Open outbound network connections |
| `network.listen` | `(portSpec?)` | Bind server sockets |
| `threads.create` | none | Create new threads |
| `native.load` | `(pattern?)` | Load native libraries |
| `env.read` | `(pattern?)` | Read environment variables |
| `system.property.read` | `(pattern?)` | Read system properties |
| `system.property.write` | `(pattern?)` | Write system properties |

### Argument Details

**Host patterns** for `network.outbound`:
- `*` — matches exactly one DNS segment (e.g., `*.example.com` matches `api.example.com`)
- `**` — matches one or more DNS segments (e.g., `**.example.com` matches `a.b.example.com`)

**Port specs** for `network.outbound` and `network.listen`:
- Integer: `443` — specific port
- String range: `"80-443"` — port range (inclusive)

---

## Integration with Build Tools

### Gradle

Use the jGuard Gradle plugin instead of invoking the CLI directly:

```groovy
plugins {
    id 'io.jguard.policy'
}
```

### Maven

Use `exec-maven-plugin`:

```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    <executions>
        <execution>
            <goals><goal>exec</goal></goals>
            <phase>compile</phase>
            <configuration>
                <executable>jguard</executable>
                <arguments>
                    <argument>compile</argument>
                    <argument>-o</argument>
                    <argument>${project.build.outputDirectory}/policy.bin</argument>
                    <argument>src/main/java/module-info.jguard</argument>
                </arguments>
            </configuration>
        </execution>
    </executions>
</plugin>
```

### Make / Shell Scripts

```bash
jguard compile -o target/policy.bin src/main/java/module-info.jguard
```

---

## See Also

- [Policy Descriptor Specification](../docs/spec/jguard-policy-descriptor.md)
- [jGuard README](../README.md)
- [Agent Configuration](../agent/README.md)
