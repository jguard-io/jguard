# CLI Tools Demo

This demo showcases jGuard's **CLI tools** for policy management.

## Prerequisites

Build and install the jGuard CLI from the repository root:

```bash
cd ../..
./gradlew :cli:installDist
```

Two CLIs are installed:
- `jguardc` - Policy compiler
- `jguard` - Policy inspection and validation tools

The binaries will be available at:
```
cli/build/install/jguardc/bin/jguardc
cli/build/install/jguard/bin/jguard
```

For convenience, add them to your PATH:
```bash
export PATH="$PATH:$(pwd)/cli/build/install/jguardc/bin:$(pwd)/cli/build/install/jguard/bin"
```

## Demo Commands

### 1. Compile a Policy

Compile a `.jguard` source file to binary format:

```bash
cd samples/sandbox-cli-tools
mkdir -p build

# Compile with JSON output for debugging
jguardc -o build/sample-policy.bin \
        --json build/sample-policy.json \
        policies-src/sample.jguard

# View the JSON output
cat build/sample-policy.json | jq .
```

### 2. Inspect a Policy File

Examine the contents of a compiled policy:

```bash
jguard inspect build/sample-policy.bin
```

Expected output:
```
Policy: build/sample-policy.bin

Format version: 2
Modules: 1

  Module: com.example.sample
  Entitlements: 3
    - fs.read
    - network.outbound
    - threads.create
```

With verbose details:
```bash
jguard inspect -v build/sample-policy.bin
```

### 3. Diff Two Policies

Compare a base policy with an override to see differences:

```bash
# Compile both policies
jguardc -o build/base.bin policies-src/base.jguard
jguardc -o build/override.bin policies-src/override.jguard

# Compare them
jguard diff build/base.bin build/override.bin
```

Expected output:
```
Module: com.example.sample
  - module -> network.outbound
  - module -> native.load
  - module -> fs.read("/", "**")
  + module -> fs.read("/data", "**/*.json")
  + module -> network.outbound("trusted.com", 443)
```

### 4. Validate Override Policies

Validate that an override only contains entitlements present in the base policy:

```bash
# Compile the override policies
jguardc -o build/valid-override.bin policies-src/valid-override.jguard
jguardc -o build/invalid-override.bin policies-src/invalid-override.jguard

# Valid override (only uses entitlements from base)
jguard validate-override --embedded build/base.bin --override build/valid-override.bin

# Invalid override (grants new capability)
jguard validate-override --embedded build/base.bin --override build/invalid-override.bin
```

Valid override output:
```
Override is valid (all entitlements are subsets of embedded policy).
  Embedded modules: 1
  Override modules: 1
```

Invalid override output:
```
Error: Override for module 'com.example.sample' contains 1 entitlement(s) not in embedded policy:
  - module -> env.read

Override validation FAILED.
Overrides can only RESTRICT capabilities, not grant new ones.
```

## Sample Files

This demo includes:

| File | Purpose |
|------|---------|
| `policies-src/sample.jguard` | Basic sample policy |
| `policies-src/base.jguard` | Base policy for diff/validation demos |
| `policies-src/override.jguard` | Restrictive override for diff demo |
| `policies-src/valid-override.jguard` | Valid override (uses subset of base entitlements) |
| `policies-src/invalid-override.jguard` | Invalid override (adds `env.read` not in base) |
| `policies-src/invalid.jguard` | Policy with syntax error for error handling demo |

## Error Handling

The CLI provides helpful error messages in gcc/clang style:

```bash
jguardc -o build/bad.bin policies-src/invalid.jguard
```

Output:
```
policies-src/invalid.jguard:9:23: error: Unknown capability: 'bad.capability'
```

## Use Cases

### Development Workflow
1. Write policy in `.jguard` format
2. Compile with `jguardc`
3. Test with `jguard inspect`
4. Compare versions with `jguard diff`

### Operations Workflow
1. Validate overrides before deployment: `jguard validate-override`
2. Inspect policies: `jguard inspect`
3. Compare policy versions: `jguard diff`

### Debugging
1. Use `-v` flag for verbose output
2. Use `--json` output for programmatic parsing
3. Use `jguard diff` to compare expected vs actual

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (validation failed, file not found, etc.) |
| 2 | Invalid command-line arguments |

## See Also

- [CLI Tools Reference](../../cli/README.md)
- [Policy Descriptor Specification](../../docs/spec/jguard-policy-descriptor.md)
- [jGuard README](../../README.md)
