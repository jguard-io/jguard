/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.serialization;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.Writer;
import org.jguard.policy.model.CapabilityArgument;
import org.jguard.policy.model.CapabilityGrant;
import org.jguard.policy.model.Entitlement;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.model.SubjectPattern;

/**
 * Writes a policy descriptor to JSON format.
 *
 * <p>The JSON output is deterministic: identical policies produce byte-identical JSON output. This
 * is achieved by:
 *
 * <ul>
 *   <li>Sorting entitlements in the policy model
 *   <li>Using consistent key ordering
 *   <li>Using consistent indentation
 * </ul>
 */
public final class JsonPolicyWriter {

  private static final ObjectMapper MAPPER = createMapper();

  private static ObjectMapper createMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.enable(SerializationFeature.INDENT_OUTPUT);
    mapper.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
    return mapper;
  }

  private JsonPolicyWriter() {
    // Static utility class
  }

  /**
   * Writes a policy descriptor to JSON string.
   *
   * @param policy the policy descriptor to write
   * @return the JSON string
   * @throws IOException if an I/O error occurs
   */
  public static String toJson(PolicyDescriptor policy) throws IOException {
    StringWriter writer = new StringWriter();
    write(policy, writer);
    return writer.toString();
  }

  /**
   * Writes a policy descriptor to an output stream.
   *
   * @param policy the policy descriptor to write
   * @param out the output stream to write to
   * @throws IOException if an I/O error occurs
   */
  public static void write(PolicyDescriptor policy, OutputStream out) throws IOException {
    JsonGenerator gen = MAPPER.createGenerator(out);
    writePolicy(gen, policy);
    gen.flush();
  }

  /**
   * Writes a policy descriptor to a writer.
   *
   * @param policy the policy descriptor to write
   * @param out the writer to write to
   * @throws IOException if an I/O error occurs
   */
  public static void write(PolicyDescriptor policy, Writer out) throws IOException {
    JsonGenerator gen = MAPPER.createGenerator(out);
    writePolicy(gen, policy);
    gen.flush();
  }

  private static void writePolicy(JsonGenerator gen, PolicyDescriptor policy) throws IOException {
    gen.writeStartObject();

    gen.writeNumberField("formatVersion", policy.formatVersion());
    gen.writeStringField("moduleName", policy.moduleName());

    gen.writeArrayFieldStart("entitlements");
    for (Entitlement entitlement : policy.entitlements()) {
      writeEntitlement(gen, entitlement);
    }
    gen.writeEndArray();

    gen.writeEndObject();
  }

  private static void writeEntitlement(JsonGenerator gen, Entitlement entitlement)
      throws IOException {
    gen.writeStartObject();
    writeSubject(gen, entitlement.subject());
    writeCapability(gen, entitlement.capability());
    gen.writeEndObject();
  }

  private static void writeSubject(JsonGenerator gen, SubjectPattern subject) throws IOException {
    gen.writeStringField("subject", subject.toCanonicalString());
    gen.writeStringField("subjectType", subject.type().name());
    if (subject.packageName() != null) {
      gen.writeStringField("packageName", subject.packageName());
    }
  }

  private static void writeCapability(JsonGenerator gen, CapabilityGrant capability)
      throws IOException {
    gen.writeStringField("capability", capability.name());
    if (capability.hasArguments()) {
      gen.writeArrayFieldStart("arguments");
      for (CapabilityArgument arg : capability.arguments()) {
        writeArgument(gen, arg);
      }
      gen.writeEndArray();
    }
  }

  private static void writeArgument(JsonGenerator gen, CapabilityArgument arg) throws IOException {
    gen.writeStartObject();
    switch (arg) {
      case CapabilityArgument.StringArg s -> {
        gen.writeStringField("type", "string");
        gen.writeStringField("value", s.value());
      }
      case CapabilityArgument.IntegerArg i -> {
        gen.writeStringField("type", "integer");
        gen.writeNumberField("value", i.value());
      }
    }
    gen.writeEndObject();
  }
}
