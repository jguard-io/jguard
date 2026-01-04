# jGuard CLI Tools

Command-line tools for working with jGuard policy descriptors.

## jguardc - Policy Compiler

Compiles `module-info.jguard` policy descriptors into binary format for runtime enforcement.

### Installation

Build and install the distribution:

```bash
./gradlew :cli:installDist
```

The `jguardc` binary will be available at:
```
cli/build/install/jguardc/bin/jguardc
```

### Usage

```bash
jguardc [OPTIONS] <source>
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `<source>` | Path to the `module-info.jguard` source file |

#### Options

| Option | Description |
|--------|-------------|
| `-o, --output <path>` | **(Required)** Output path for the compiled binary policy file |
| `--json <path>` | Also output JSON format to the specified path |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Show help message and exit |
| `-V, --version` | Print version information and exit |

### Examples

**Basic compilation:**
```bash
jguardc -o build/policy.bin src/main/java/module-info.jguard
```

**With JSON output for debugging:**
```bash
jguardc -o build/policy.bin --json build/policy.json src/main/java/module-info.jguard
```

**Verbose mode:**
```bash
jguardc -v -o build/policy.bin src/main/java/module-info.jguard
```

Output:
```
jguardc: compiling src/main/java/module-info.jguard
jguardc: wrote build/policy.bin
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Compilation successful |
| 1 | Compilation failed (syntax error, validation error, or I/O error) |
| 2 | Invalid command-line arguments |

### Error Output

Errors are printed to stderr in gcc/clang style:

```
src/main/java/module-info.jguard:5:23: error: Unknown capability: 'bad.capability'
```

Format: `file:line:column: severity: message`

### Output Formats

#### Binary Format (`.bin`)

Compact binary representation for runtime loading. Structure:

```
Header:
  magic:    4 bytes ("JGRD")
  version:  1 byte  (format version)

Module:
  name:     length-prefixed UTF-8 string

Entitlements:
  count:    2 bytes (unsigned short)
  entries:  repeated entitlement records
```

#### JSON Format (`.json`)

Human-readable format for debugging and inspection:

```json
{
  "formatVersion": 1,
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
```

### Integration with Build Tools

#### Gradle

Use the jGuard Gradle plugin instead of invoking `jguardc` directly:

```groovy
plugins {
    id 'org.jguard.policy'
}
```

#### Maven

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
                <executable>jguardc</executable>
                <arguments>
                    <argument>-o</argument>
                    <argument>${project.build.outputDirectory}/policy.bin</argument>
                    <argument>src/main/java/module-info.jguard</argument>
                </arguments>
            </configuration>
        </execution>
    </executions>
</plugin>
```

#### Make / Shell Scripts

```bash
jguardc -o target/policy.bin src/main/java/module-info.jguard
```

### Supported Capabilities

The compiler validates that only known capabilities are used:

| Capability | Arguments | Description |
|------------|-----------|-------------|
| `fs.read` | `(root, glob)` | Read files matching glob under root |
| `fs.write` | `(root, glob)` | Write files matching glob under root |
| `network.outbound` | none | Make outbound network connections |
| `network.listen` | `(port)` | Listen on a port |
| `threads.create` | none | Spawn new threads |
| `native.load` | none | Load native libraries |

### See Also

- [Policy Descriptor Specification](../docs/spec/jguard-policy-descriptor.md)
- [jGuard README](../README.md)
