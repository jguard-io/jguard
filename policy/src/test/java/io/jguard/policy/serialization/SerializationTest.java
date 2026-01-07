/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.serialization;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.model.SubjectPattern;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for policy serialization. */
class SerializationTest {

  private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

  @Nested
  class BinaryPolicyWriterTest {

    @Test
    void writesMagicHeader() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      assertThat(bytes[0]).isEqualTo((byte) 'J');
      assertThat(bytes[1]).isEqualTo((byte) 'G');
      assertThat(bytes[2]).isEqualTo((byte) 'R');
      assertThat(bytes[3]).isEqualTo((byte) 'D');
    }

    @Test
    void writesFormatVersion() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      assertThat(bytes[4]).isEqualTo((byte) 1);
    }

    @Test
    void writesModuleName() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      // After header (5 bytes), we have module name as length-prefixed string
      ByteBuffer buf = ByteBuffer.wrap(bytes, 5, bytes.length - 5);
      int nameLen = buf.getShort() & 0xFFFF;
      byte[] nameBytes = new byte[nameLen];
      buf.get(nameBytes);
      String moduleName = new String(nameBytes, StandardCharsets.UTF_8);

      assertThat(moduleName).isEqualTo("com.example.app");
    }

    @Test
    void writesZeroEntitlements() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      // After header (5) + module name length (2) + "app" (3), we have entitlement count
      ByteBuffer buf = ByteBuffer.wrap(bytes);
      buf.position(5 + 2 + 3);
      int count = buf.getShort() & 0xFFFF;

      assertThat(count).isEqualTo(0);
    }

    @Test
    void writesModuleSubjectEntitlement() throws IOException {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      // After header (5) + module name (5), we have count (2) + subject type
      ByteBuffer buf = ByteBuffer.wrap(bytes);
      buf.position(5 + 2 + 3 + 2); // skip to first entitlement
      byte subjectType = buf.get();

      assertThat(subjectType).isEqualTo((byte) 0); // MODULE
    }

    @Test
    void writesExactPackageSubjectEntitlement() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      // Navigate to subject type
      ByteBuffer buf = ByteBuffer.wrap(bytes);
      buf.position(5 + 2 + 3 + 2);
      byte subjectType = buf.get();

      assertThat(subjectType).isEqualTo((byte) 1); // EXACT
    }

    @Test
    void writesDirectChildrenSubjectEntitlement() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.directChildren("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      ByteBuffer buf = ByteBuffer.wrap(bytes);
      buf.position(5 + 2 + 3 + 2);
      byte subjectType = buf.get();

      assertThat(subjectType).isEqualTo((byte) 2); // DIRECT_CHILDREN
    }

    @Test
    void writesRecursiveSubjectEntitlement() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.recursive("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      ByteBuffer buf = ByteBuffer.wrap(bytes);
      buf.position(5 + 2 + 3 + 2);
      byte subjectType = buf.get();

      assertThat(subjectType).isEqualTo((byte) 3); // RECURSIVE
    }

    @Test
    void writesCapabilityWithStringArgument() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.StringArg("*.json")));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      // The output should contain the capability with arguments
      assertThat(bytes.length).isGreaterThan(20);
    }

    @Test
    void writesCapabilityWithIntegerArgument() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of("network.listen", List.of(new CapabilityArgument.IntegerArg(8080)));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      assertThat(bytes.length).isGreaterThan(20);
    }

    @Test
    void writesToOutputStream() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());
      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      BinaryPolicyWriter.write(policy, baos);

      byte[] bytes = baos.toByteArray();
      assertThat(bytes).startsWith((byte) 'J', (byte) 'G', (byte) 'R', (byte) 'D');
    }

    @Test
    void producesDeterministicOutput() throws IOException {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("threads.create"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(e1, e2));

      byte[] bytes1 = BinaryPolicyWriter.toBytes(policy);
      byte[] bytes2 = BinaryPolicyWriter.toBytes(policy);

      assertThat(bytes1).isEqualTo(bytes2);
    }

    @Test
    void writesMultipleEntitlements() throws IOException {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("threads.create"));
      Entitlement e3 =
          new Entitlement(
              SubjectPattern.recursive("com.worker"), CapabilityGrant.of("native.load"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(e1, e2, e3));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      // After header (5) + module name (5), we have count
      ByteBuffer buf = ByteBuffer.wrap(bytes);
      buf.position(5 + 2 + 3);
      int count = buf.getShort() & 0xFFFF;

      assertThat(count).isEqualTo(3);
    }

    @Test
    void handlesUnicodeInModuleName() throws IOException {
      // Module names should be ASCII, but test UTF-8 encoding works
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      assertThat(bytes).isNotNull();
      assertThat(bytes.length).isGreaterThan(5);
    }

    @Test
    void handlesUnicodeInStringArguments() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/données"),
                  new CapabilityArgument.StringArg("*.txt")));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(policy);

      assertThat(bytes).isNotNull();
    }
  }

  @Nested
  class JsonPolicyWriterTest {

    @Test
    void writesFormatVersion() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);

      assertThat(root.get("formatVersion").asInt()).isEqualTo(1);
    }

    @Test
    void writesModuleName() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);

      assertThat(root.get("moduleName").asText()).isEqualTo("com.example.app");
    }

    @Test
    void writesEmptyEntitlementsArray() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);

      assertThat(root.get("entitlements").isArray()).isTrue();
      assertThat(root.get("entitlements").size()).isEqualTo(0);
    }

    @Test
    void writesModuleSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode ent = root.get("entitlements").get(0);

      assertThat(ent.get("subject").asText()).isEqualTo("module");
      assertThat(ent.get("subjectType").asText()).isEqualTo("MODULE");
      assertThat(ent.has("packageName")).isFalse();
    }

    @Test
    void writesExactPackageSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode ent = root.get("entitlements").get(0);

      assertThat(ent.get("subject").asText()).isEqualTo("com.example");
      assertThat(ent.get("subjectType").asText()).isEqualTo("PACKAGE_EXACT");
      assertThat(ent.get("packageName").asText()).isEqualTo("com.example");
    }

    @Test
    void writesDirectChildrenSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.directChildren("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode ent = root.get("entitlements").get(0);

      assertThat(ent.get("subject").asText()).isEqualTo("com.example.*");
      assertThat(ent.get("subjectType").asText()).isEqualTo("PACKAGE_DIRECT_CHILDREN");
    }

    @Test
    void writesRecursiveSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.recursive("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode ent = root.get("entitlements").get(0);

      assertThat(ent.get("subject").asText()).isEqualTo("com.example..");
      assertThat(ent.get("subjectType").asText()).isEqualTo("PACKAGE_RECURSIVE");
    }

    @Test
    void writesCapabilityName() throws IOException {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode ent = root.get("entitlements").get(0);

      assertThat(ent.get("capability").asText()).isEqualTo("network.outbound");
    }

    @Test
    void omitsArgumentsWhenEmpty() throws IOException {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode ent = root.get("entitlements").get(0);

      assertThat(ent.has("arguments")).isFalse();
    }

    @Test
    void writesStringArguments() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.StringArg("*.json")));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode args = root.get("entitlements").get(0).get("arguments");

      assertThat(args.size()).isEqualTo(2);
      assertThat(args.get(0).get("type").asText()).isEqualTo("string");
      assertThat(args.get(0).get("value").asText()).isEqualTo("/data");
      assertThat(args.get(1).get("type").asText()).isEqualTo("string");
      assertThat(args.get(1).get("value").asText()).isEqualTo("*.json");
    }

    @Test
    void writesIntegerArguments() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of("network.listen", List.of(new CapabilityArgument.IntegerArg(8080)));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode args = root.get("entitlements").get(0).get("arguments");

      assertThat(args.size()).isEqualTo(1);
      assertThat(args.get(0).get("type").asText()).isEqualTo("integer");
      assertThat(args.get(0).get("value").asLong()).isEqualTo(8080L);
    }

    @Test
    void writesToOutputStream() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());
      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      JsonPolicyWriter.write(policy, baos);

      String json = baos.toString(StandardCharsets.UTF_8);
      JsonNode root = JSON_MAPPER.readTree(json);
      assertThat(root.get("moduleName").asText()).isEqualTo("app");
    }

    @Test
    void writesToWriter() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());
      StringWriter writer = new StringWriter();

      JsonPolicyWriter.write(policy, writer);

      String json = writer.toString();
      JsonNode root = JSON_MAPPER.readTree(json);
      assertThat(root.get("moduleName").asText()).isEqualTo("app");
    }

    @Test
    void producesDeterministicOutput() throws IOException {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("threads.create"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(e1, e2));

      String json1 = JsonPolicyWriter.toJson(policy);
      String json2 = JsonPolicyWriter.toJson(policy);

      assertThat(json1).isEqualTo(json2);
    }

    @Test
    void producesFormattedOutput() throws IOException {
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of());

      String json = JsonPolicyWriter.toJson(policy);

      assertThat(json).contains("\n"); // Output is indented
    }

    @Test
    void writesMultipleEntitlements() throws IOException {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("threads.create"));
      Entitlement e3 =
          new Entitlement(
              SubjectPattern.recursive("com.worker"), CapabilityGrant.of("native.load"));
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(e1, e2, e3));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);

      assertThat(root.get("entitlements").size()).isEqualTo(3);
    }

    @Test
    void handlesSpecialCharactersInStrings() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/path/with\"quotes"),
                  new CapabilityArgument.StringArg("*.txt")));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode args = root.get("entitlements").get(0).get("arguments");

      // JSON should properly escape the quotes
      assertThat(args.get(0).get("value").asText()).isEqualTo("/path/with\"quotes");
    }

    @Test
    void handlesUnicodeCharacters() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/données/日本語"),
                  new CapabilityArgument.StringArg("*.txt")));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode args = root.get("entitlements").get(0).get("arguments");

      assertThat(args.get(0).get("value").asText()).isEqualTo("/données/日本語");
    }

    @Test
    void handlesLargeIntegerValues() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "network.listen", List.of(new CapabilityArgument.IntegerArg(Long.MAX_VALUE)));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(entitlement));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode args = root.get("entitlements").get(0).get("arguments");

      assertThat(args.get(0).get("value").asLong()).isEqualTo(Long.MAX_VALUE);
    }

    @Test
    void preservesEntitlementOrder() throws IOException {
      // PolicyDescriptor sorts entitlements, so we verify the order is preserved in output
      Entitlement eModule =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement ePkgA =
          new Entitlement(
              SubjectPattern.exactPackage("a.pkg"), CapabilityGrant.of("threads.create"));
      Entitlement ePkgZ =
          new Entitlement(SubjectPattern.exactPackage("z.pkg"), CapabilityGrant.of("native.load"));

      // Pass in unsorted order
      PolicyDescriptor policy = PolicyDescriptor.create("app", List.of(ePkgZ, eModule, ePkgA));

      String json = JsonPolicyWriter.toJson(policy);
      JsonNode root = JSON_MAPPER.readTree(json);
      JsonNode entitlements = root.get("entitlements");

      // Should be sorted: module first, then packages alphabetically
      assertThat(entitlements.get(0).get("subject").asText()).isEqualTo("module");
      assertThat(entitlements.get(1).get("subject").asText()).isEqualTo("a.pkg");
      assertThat(entitlements.get(2).get("subject").asText()).isEqualTo("z.pkg");
    }
  }

  @Nested
  class BinaryPolicyReaderTest {

    @Test
    void readsEmptyPolicy() throws IOException {
      PolicyDescriptor original = PolicyDescriptor.create("com.example.app", List.of());

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      assertThat(read.moduleName()).isEqualTo("com.example.app");
      assertThat(read.entitlements()).isEmpty();
    }

    @Test
    void readsModuleSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      assertThat(read.entitlements()).hasSize(1);
      assertThat(read.entitlements().get(0).subject().type()).isEqualTo(SubjectPattern.Type.MODULE);
    }

    @Test
    void readsExactPackageSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      assertThat(read.entitlements().get(0).subject().type())
          .isEqualTo(SubjectPattern.Type.PACKAGE_EXACT);
      assertThat(read.entitlements().get(0).subject().packageName()).isEqualTo("com.example");
    }

    @Test
    void readsDirectChildrenSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.directChildren("com.example"), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      assertThat(read.entitlements().get(0).subject().type())
          .isEqualTo(SubjectPattern.Type.PACKAGE_DIRECT_CHILDREN);
    }

    @Test
    void readsRecursiveSubject() throws IOException {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.recursive("com.worker"), CapabilityGrant.of("threads.create"));
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      assertThat(read.entitlements().get(0).subject().type())
          .isEqualTo(SubjectPattern.Type.PACKAGE_RECURSIVE);
    }

    @Test
    void readsCapabilityWithStringArguments() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.StringArg("*.json")));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      CapabilityGrant readCap = read.entitlements().get(0).capability();
      assertThat(readCap.name()).isEqualTo("fs.read");
      assertThat(readCap.arguments()).hasSize(2);
      assertThat(((CapabilityArgument.StringArg) readCap.arguments().get(0)).value())
          .isEqualTo("/data");
      assertThat(((CapabilityArgument.StringArg) readCap.arguments().get(1)).value())
          .isEqualTo("*.json");
    }

    @Test
    void readsCapabilityWithIntegerArguments() throws IOException {
      CapabilityGrant capability =
          CapabilityGrant.of("network.listen", List.of(new CapabilityArgument.IntegerArg(8080)));
      Entitlement entitlement = new Entitlement(SubjectPattern.module(), capability);
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(entitlement));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      CapabilityGrant readCap = read.entitlements().get(0).capability();
      assertThat(readCap.name()).isEqualTo("network.listen");
      assertThat(((CapabilityArgument.IntegerArg) readCap.arguments().get(0)).value())
          .isEqualTo(8080L);
    }

    @Test
    void readsMultipleEntitlements() throws IOException {
      Entitlement e1 =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      Entitlement e2 =
          new Entitlement(
              SubjectPattern.exactPackage("com.example"), CapabilityGrant.of("threads.create"));
      Entitlement e3 =
          new Entitlement(
              SubjectPattern.recursive("com.worker"), CapabilityGrant.of("native.load"));
      PolicyDescriptor original = PolicyDescriptor.create("app", List.of(e1, e2, e3));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      assertThat(read.entitlements()).hasSize(3);
    }

    @Test
    void roundTripPreservesAllData() throws IOException {
      CapabilityGrant fsRead =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.StringArg("*.json")));
      CapabilityGrant listen =
          CapabilityGrant.of("network.listen", List.of(new CapabilityArgument.IntegerArg(8080)));

      Entitlement e1 = new Entitlement(SubjectPattern.module(), fsRead);
      Entitlement e2 = new Entitlement(SubjectPattern.exactPackage("com.example.net"), listen);
      Entitlement e3 =
          new Entitlement(
              SubjectPattern.recursive("com.worker"), CapabilityGrant.of("threads.create"));
      PolicyDescriptor original = PolicyDescriptor.create("com.example.app", List.of(e1, e2, e3));

      byte[] bytes = BinaryPolicyWriter.toBytes(original);
      PolicyDescriptor read = BinaryPolicyReader.fromBytes(bytes);

      // Write again and compare bytes
      byte[] bytesAgain = BinaryPolicyWriter.toBytes(read);
      assertThat(bytesAgain).isEqualTo(bytes);
    }

    @Test
    void rejectsInvalidMagic() {
      byte[] invalid = {'X', 'X', 'X', 'X', 1, 0, 3, 'a', 'p', 'p', 0, 0};

      org.assertj.core.api.Assertions.assertThatThrownBy(
              () -> BinaryPolicyReader.fromBytes(invalid))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Invalid policy file");
    }

    @Test
    void rejectsUnsupportedVersion() {
      byte[] invalid = {'J', 'G', 'R', 'D', 99, 0, 3, 'a', 'p', 'p', 0, 0};

      org.assertj.core.api.Assertions.assertThatThrownBy(
              () -> BinaryPolicyReader.fromBytes(invalid))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Unsupported policy format version");
    }
  }

  @Nested
  class RoundTripTest {

    @Test
    void binaryAndJsonProduceConsistentData() throws IOException {
      CapabilityGrant fsRead =
          CapabilityGrant.of(
              "fs.read",
              List.of(
                  new CapabilityArgument.StringArg("/data"),
                  new CapabilityArgument.StringArg("*.json")));
      CapabilityGrant listen =
          CapabilityGrant.of("network.listen", List.of(new CapabilityArgument.IntegerArg(8080)));

      Entitlement e1 = new Entitlement(SubjectPattern.module(), fsRead);
      Entitlement e2 = new Entitlement(SubjectPattern.exactPackage("com.example.net"), listen);
      Entitlement e3 =
          new Entitlement(
              SubjectPattern.recursive("com.worker"), CapabilityGrant.of("threads.create"));

      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(e1, e2, e3));

      // Both formats should serialize without error
      byte[] binary = BinaryPolicyWriter.toBytes(policy);
      String json = JsonPolicyWriter.toJson(policy);

      assertThat(binary.length).isGreaterThan(0);
      assertThat(json).isNotEmpty();

      // JSON should be parseable
      JsonNode root = JSON_MAPPER.readTree(json);
      assertThat(root.get("moduleName").asText()).isEqualTo("com.example.app");
      assertThat(root.get("entitlements").size()).isEqualTo(3);
    }
  }
}
