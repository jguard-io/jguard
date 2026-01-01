# jGuard Policy Module

The policy module provides the compiler infrastructure for jGuard policy descriptors. It transforms human-readable `.jguard` policy files into a deterministic, machine-readable format that the jGuard runtime uses for capability enforcement.

## Overview

```
┌─────────────────┐     ┌─────────┐     ┌────────┐     ┌───────────┐     ┌────────────┐
│ .jguard source  │────▶│  Lexer  │────▶│ Parser │────▶│ Validator │────▶│ Serializer │
└─────────────────┘     └─────────┘     └────────┘     └───────────┘     └────────────┘
                            │               │               │                   │
                            ▼               ▼               ▼                   ▼
                         Tokens           AST          Diagnostics      JSON / Binary
```

## Policy Descriptor Language

### Grammar

```ebnf
policy-file     = "security" "module" module-name "{" entitlement* "}" ;

module-name     = identifier ("." identifier)* ;

entitlement     = "entitle" subject "to" capability ";" ;

subject         = "module"                    (* entire module *)
                | package-pattern ;

package-pattern = identifier ("." identifier)* [ ".*" | ".." ] ;
                  (* .* = direct subpackages, .. = recursive *)

capability      = capability-name [ "(" arguments ")" ] ;

capability-name = identifier ("." identifier)* ;

arguments       = argument ("," argument)* ;

argument        = STRING | INTEGER | IDENTIFIER ;
```

### Example Policy

```java
/*
 * SPDX-License-Identifier: Apache-2.0
 */
security module com.example.myapp {

    // Grant filesystem read access to the entire module
    entitle module to fs.read("/data", "*.json");

    // Grant network access to specific package
    entitle com.example.myapp.net to network.outbound;

    // Grant to direct child packages only
    entitle com.example.myapp.handlers.* to network.listen(8080);

    // Grant recursively to package and all descendants
    entitle com.example.myapp.worker.. to threads.spawn;

}
```

### Subject Patterns

| Pattern | Meaning |
|---------|---------|
| `module` | The entire module (all packages) |
| `com.example` | Exact package match |
| `com.example.*` | Direct child packages only |
| `com.example..` | Package and all descendants (recursive) |

### Supported Capabilities

| Capability | Arguments | Description |
|------------|-----------|-------------|
| `fs.read(root, glob)` | 2 strings | Read files under `root` matching `glob` |
| `fs.write(root, glob)` | 2 strings | Write files under `root` matching `glob` |
| `network.outbound` | none | Make outbound network connections |
| `network.listen(port)` | 1 integer | Listen on a specific port |
| `threads.spawn` | none | Create new threads |
| `native.load` | none | Load native libraries |

### Lexical Elements

- **Comments**: Line (`// ...`) and block (`/* ... */`)
- **Strings**: Double-quoted with escape sequences (`\"`, `\\`, `\n`, `\t`, `\r`)
- **Integers**: Decimal only (no hex/octal)
- **Identifiers**: Java identifier rules (`[a-zA-Z_][a-zA-Z0-9_]*`)

### Validation Rules

1. **Module names** must be valid Java identifiers (no keywords like `class`, `public`)
2. **Package patterns** must be valid Java package names
3. **Capabilities** must be recognized and have correct argument counts/types
4. **Argument types** must match the capability signature

## Module Structure

```
policy/src/main/java/org/jguard/policy/
├── ast/                    # Abstract Syntax Tree nodes
│   ├── Argument.java       # Capability arguments (string, integer, identifier)
│   ├── Capability.java     # Capability with name and arguments
│   ├── EntitlementDeclaration.java
│   ├── PackagePattern.java # Package matching patterns
│   ├── PolicyFile.java     # Root AST node
│   ├── SourceLocation.java # Line/column tracking
│   └── Subject.java        # Module or package subject
├── compiler/               # High-level compilation API
│   ├── CompilationResult.java
│   └── PolicyCompiler.java
├── lexer/                  # Tokenization
│   ├── Lexer.java
│   ├── Token.java
│   └── TokenType.java
├── model/                  # Semantic model (output)
│   ├── CapabilityArgument.java
│   ├── CapabilityGrant.java
│   ├── Entitlement.java
│   ├── PolicyBuilder.java
│   ├── PolicyDescriptor.java
│   └── SubjectPattern.java
├── parser/                 # Syntax analysis
│   └── Parser.java
├── serialization/          # Output formats
│   ├── BinaryPolicyWriter.java
│   └── JsonPolicyWriter.java
└── validation/             # Semantic validation
    └── PolicyValidator.java
```

## API Usage

### Compiling a Policy File

```java
import org.jguard.policy.compiler.PolicyCompiler;
import org.jguard.policy.compiler.CompilationResult;

Path policyFile = Path.of("module-info.jguard");
CompilationResult result = PolicyCompiler.compile(policyFile);

if (result.hasErrors()) {
    for (CompilationResult.Diagnostic d : result.diagnostics()) {
        System.err.printf("%s:%d:%d: %s%n",
            d.sourcePath(), d.line(), d.column(), d.message());
    }
} else {
    PolicyDescriptor policy = result.policy();
    // Use the compiled policy...
}
```

### Serializing to JSON

```java
import org.jguard.policy.serialization.JsonPolicyWriter;

String json = JsonPolicyWriter.toJson(policy);

// Or write to a stream
try (OutputStream out = Files.newOutputStream(outputPath)) {
    JsonPolicyWriter.write(policy, out);
}
```

### Serializing to Binary

```java
import org.jguard.policy.serialization.BinaryPolicyWriter;

byte[] binary = BinaryPolicyWriter.toBytes(policy);

// Or write to a stream
try (OutputStream out = Files.newOutputStream(outputPath)) {
    BinaryPolicyWriter.write(policy, out);
}
```

### Building Policies Programmatically

```java
import org.jguard.policy.model.*;

PolicyDescriptor policy = PolicyDescriptor.create(
    "com.example.app",
    List.of(
        new Entitlement(
            SubjectPattern.module(),
            CapabilityGrant.of("network.outbound")),
        new Entitlement(
            SubjectPattern.exactPackage("com.example.app.io"),
            CapabilityGrant.of("fs.read", List.of(
                new CapabilityArgument.StringArg("/data"),
                new CapabilityArgument.StringArg("*.json"))))
    )
);
```

## Output Formats

### JSON Format

```json
{
  "formatVersion": 1,
  "moduleName": "com.example.app",
  "entitlements": [
    {
      "subject": "module",
      "subjectType": "MODULE",
      "capability": "network.outbound"
    },
    {
      "subject": "com.example.app.io",
      "subjectType": "PACKAGE_EXACT",
      "packageName": "com.example.app.io",
      "capability": "fs.read",
      "arguments": [
        { "type": "string", "value": "/data" },
        { "type": "string", "value": "*.json" }
      ]
    }
  ]
}
```

### Binary Format

```
Header:
  magic:         4 bytes ("JGRD")
  version:       1 byte  (format version, currently 1)

Module:
  moduleName:    string  (length-prefixed UTF-8)

Entitlements:
  count:         2 bytes (unsigned short, big-endian)
  entitlements:  repeated entitlement

Entitlement:
  subjectType:   1 byte  (0=MODULE, 1=EXACT, 2=DIRECT_CHILDREN, 3=RECURSIVE)
  packageName:   string  (length-prefixed UTF-8, omitted if subjectType=0)
  capability:    string  (length-prefixed UTF-8)
  argCount:      1 byte
  arguments:     repeated argument

Argument:
  type:          1 byte  (0=string, 1=integer)
  value:         string or long (8 bytes, big-endian)

String:
  length:        2 bytes (unsigned short, big-endian)
  data:          UTF-8 bytes
```

## Design Principles

### Deterministic Output

Identical policy sources produce byte-identical output:
- Entitlements are sorted by subject (module first, then packages alphabetically)
- Duplicate entitlements are deduplicated
- JSON uses consistent formatting and key ordering

### Fail-Fast Validation

The validator catches errors early with precise diagnostics:
- Line and column numbers for every error
- Clear messages explaining what went wrong
- All errors reported (not just the first one)

### Immutability

All model classes are immutable records:
- Thread-safe by construction
- Defensive copies prevent modification
- Safe to cache and share

### Separation of Concerns

The pipeline has distinct phases:
1. **Lexer**: Character stream → Token stream
2. **Parser**: Token stream → AST
3. **Validator**: AST → Validated AST + Diagnostics
4. **Builder**: AST → Semantic Model
5. **Serializer**: Model → Output format

## Testing

Run the test suite:

```bash
./gradlew :policy:test
```

The test suite includes:
- **LexerTest**: Token recognition, escape sequences, error recovery
- **ParserTest**: Grammar coverage, error messages, location tracking
- **AstTest**: Node construction, immutability, defensive copies
- **ModelTest**: Subject patterns, capabilities, entitlements, policy descriptors
- **PolicyValidatorTest**: Module names, package patterns, capability validation
- **SerializationTest**: JSON/Binary output, determinism, round-trip consistency

## CLI Tool

The `jguardc` compiler provides command-line access:

```bash
# Compile to JSON (default)
jguardc module-info.jguard -o policy.json

# Compile to binary
jguardc module-info.jguard -o policy.bin --format binary

# See cli/README.md for full documentation
```

## Contributing

When adding new capabilities:

1. Add the capability signature to `PolicyValidator.KNOWN_CAPABILITIES`
2. Add test cases in `PolicyValidatorTest`
3. Update this README's capability table
4. Update the CLI README if user-facing behavior changes

When modifying the grammar:

1. Update `TokenType` for new lexical elements
2. Update `Lexer` for tokenization
3. Update `Parser` for syntax
4. Update `PolicyValidator` for semantic rules
5. Add comprehensive tests at each level
6. Update the EBNF grammar in this README

## License

Apache-2.0. See the repository root for full license text.
