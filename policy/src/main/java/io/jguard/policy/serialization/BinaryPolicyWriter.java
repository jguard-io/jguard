/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.serialization;

import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Denial;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.model.SubjectPattern;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Writes a policy descriptor to binary format.
 *
 * <p>Binary format specification:
 *
 * <pre>
 * Header:
 *   magic:         4 bytes ("JGRD")
 *   version:       1 byte  (format version, currently 1)
 *
 * Module:
 *   moduleName:    string  (length-prefixed UTF-8)
 *
 * Entitlements:
 *   count:         2 bytes (unsigned short, big-endian)
 *   entitlements:  repeated entitlement
 *
 * Entitlement:
 *   subjectType:   1 byte  (0=MODULE, 1=EXACT, 2=DIRECT_CHILDREN, 3=RECURSIVE)
 *   packageName:   string  (length-prefixed UTF-8, omitted if subjectType=0)
 *   capability:    string  (length-prefixed UTF-8)
 *   argCount:      1 byte
 *   arguments:     repeated argument
 *
 * Argument:
 *   type:          1 byte  (0=string, 1=integer)
 *   value:         string or long (8 bytes, big-endian)
 *
 * String:
 *   length:        2 bytes (unsigned short, big-endian)
 *   data:          UTF-8 bytes
 * </pre>
 */
public final class BinaryPolicyWriter {

  private static final byte[] MAGIC = {'J', 'G', 'R', 'D'};
  private static final byte FORMAT_VERSION_V1 = 1;
  private static final byte FORMAT_VERSION_V2 = 2;
  private static final byte FORMAT_VERSION_V3 = 3;

  private static final byte SUBJECT_MODULE = 0;
  private static final byte SUBJECT_EXACT = 1;
  private static final byte SUBJECT_DIRECT_CHILDREN = 2;
  private static final byte SUBJECT_RECURSIVE = 3;

  private static final byte ARG_STRING = 0;
  private static final byte ARG_INTEGER = 1;

  private static final byte DEFENSIVE_FALSE = 0;
  private static final byte DEFENSIVE_TRUE = 1;

  private static final byte TRUSTED_FALSE = 0;
  private static final byte TRUSTED_TRUE = 1;

  private BinaryPolicyWriter() {
    // Static utility class
  }

  // ========== V2 Format (Multi-Module) ==========

  /**
   * Writes an application policy to a byte array using v2 format.
   *
   * @param policy the application policy to write
   * @return the serialized bytes
   * @throws IOException if an I/O error occurs
   */
  public static byte[] toBytes(ApplicationPolicy policy) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    write(policy, baos);
    return baos.toByteArray();
  }

  /**
   * Writes an application policy to an output stream using v2 format.
   *
   * <p>V2 format supports multiple modules:
   *
   * <pre>
   * Header:
   *   magic:         4 bytes ("JGRD")
   *   version:       1 byte  (3)
   *
   * Modules:
   *   count:         2 bytes (unsigned short)
   *   modules:       repeated module
   *
   * Module:
   *   moduleName:    string  (length-prefixed UTF-8)
   *   trusted:       1 byte  (0=false, 1=true)
   *   entitlements:  count (2 bytes) + repeated entitlement
   *   denials:       count (2 bytes) + repeated denial
   * </pre>
   *
   * @param policy the application policy to write
   * @param out the output stream to write to
   * @throws IOException if an I/O error occurs
   */
  public static void write(ApplicationPolicy policy, OutputStream out) throws IOException {
    DataOutputStream dos = new DataOutputStream(out);

    // Header
    dos.write(MAGIC);
    dos.writeByte(FORMAT_VERSION_V3);

    // Module count
    if (policy.modules().size() > 65535) {
      throw new IOException("Too many modules: " + policy.modules().size());
    }
    dos.writeShort(policy.modules().size());

    // Each module
    for (ModulePolicy module : policy.modules()) {
      writeModule(dos, module);
    }

    dos.flush();
  }

  private static void writeModule(DataOutputStream dos, ModulePolicy module) throws IOException {
    // Module name
    writeString(dos, module.moduleName());

    // Trusted flag
    dos.writeByte(module.trusted() ? TRUSTED_TRUE : TRUSTED_FALSE);

    // Entitlements
    if (module.entitlements().size() > 65535) {
      throw new IOException(
          "Too many entitlements in module "
              + module.moduleName()
              + ": "
              + module.entitlements().size());
    }
    dos.writeShort(module.entitlements().size());

    for (Entitlement entitlement : module.entitlements()) {
      writeEntitlement(dos, entitlement);
    }

    // Denials
    if (module.denials().size() > 65535) {
      throw new IOException(
          "Too many denials in module " + module.moduleName() + ": " + module.denials().size());
    }
    dos.writeShort(module.denials().size());

    for (Denial denial : module.denials()) {
      writeDenial(dos, denial);
    }
  }

  // ========== V1 Format (Single-Module, Legacy) ==========

  /**
   * Writes a policy descriptor to a byte array using v1 format.
   *
   * <p>This method is maintained for backward compatibility. New code should use {@link
   * #toBytes(ApplicationPolicy)} instead.
   *
   * @param policy the policy descriptor to write
   * @return the serialized bytes
   * @throws IOException if an I/O error occurs
   */
  public static byte[] toBytes(PolicyDescriptor policy) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    write(policy, baos);
    return baos.toByteArray();
  }

  /**
   * Writes a policy descriptor to an output stream using v1 format.
   *
   * <p>This method is maintained for backward compatibility. New code should use {@link
   * #write(ApplicationPolicy, OutputStream)} instead.
   *
   * @param policy the policy descriptor to write
   * @param out the output stream to write to
   * @throws IOException if an I/O error occurs
   */
  public static void write(PolicyDescriptor policy, OutputStream out) throws IOException {
    DataOutputStream dos = new DataOutputStream(out);

    // Header
    dos.write(MAGIC);
    dos.writeByte(FORMAT_VERSION_V1);

    // Module name
    writeString(dos, policy.moduleName());

    // Entitlements
    if (policy.entitlements().size() > 65535) {
      throw new IOException("Too many entitlements: " + policy.entitlements().size());
    }
    dos.writeShort(policy.entitlements().size());

    for (Entitlement entitlement : policy.entitlements()) {
      writeEntitlement(dos, entitlement);
    }

    dos.flush();
  }

  // ========== Common Helpers ==========

  private static void writeEntitlement(DataOutputStream dos, Entitlement entitlement)
      throws IOException {
    SubjectPattern subject = entitlement.subject();

    // Subject type
    byte subjectType =
        switch (subject.type()) {
          case MODULE -> SUBJECT_MODULE;
          case PACKAGE_EXACT -> SUBJECT_EXACT;
          case PACKAGE_DIRECT_CHILDREN -> SUBJECT_DIRECT_CHILDREN;
          case PACKAGE_RECURSIVE -> SUBJECT_RECURSIVE;
        };
    dos.writeByte(subjectType);

    // Package name (if not module)
    if (subject.type() != SubjectPattern.Type.MODULE) {
      writeString(dos, subject.packageName());
    }

    // Capability
    CapabilityGrant capability = entitlement.capability();
    writeString(dos, capability.name());

    // Arguments
    if (capability.arguments().size() > 255) {
      throw new IOException("Too many arguments: " + capability.arguments().size());
    }
    dos.writeByte(capability.arguments().size());

    for (CapabilityArgument arg : capability.arguments()) {
      writeArgument(dos, arg);
    }
  }

  private static void writeDenial(DataOutputStream dos, Denial denial) throws IOException {
    SubjectPattern subject = denial.subject();

    // Subject type
    byte subjectType =
        switch (subject.type()) {
          case MODULE -> SUBJECT_MODULE;
          case PACKAGE_EXACT -> SUBJECT_EXACT;
          case PACKAGE_DIRECT_CHILDREN -> SUBJECT_DIRECT_CHILDREN;
          case PACKAGE_RECURSIVE -> SUBJECT_RECURSIVE;
        };
    dos.writeByte(subjectType);

    // Package name (if not module)
    if (subject.type() != SubjectPattern.Type.MODULE) {
      writeString(dos, subject.packageName());
    }

    // Capability
    CapabilityGrant capability = denial.capability();
    writeString(dos, capability.name());

    // Arguments
    if (capability.arguments().size() > 255) {
      throw new IOException("Too many arguments: " + capability.arguments().size());
    }
    dos.writeByte(capability.arguments().size());

    for (CapabilityArgument arg : capability.arguments()) {
      writeArgument(dos, arg);
    }

    // Defensive flag
    dos.writeByte(denial.defensive() ? DEFENSIVE_TRUE : DEFENSIVE_FALSE);
  }

  private static void writeArgument(DataOutputStream dos, CapabilityArgument arg)
      throws IOException {
    switch (arg) {
      case CapabilityArgument.StringArg s -> {
        dos.writeByte(ARG_STRING);
        writeString(dos, s.value());
      }
      case CapabilityArgument.IntegerArg i -> {
        dos.writeByte(ARG_INTEGER);
        dos.writeLong(i.value());
      }
    }
  }

  private static void writeString(DataOutputStream dos, String s) throws IOException {
    byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > 65535) {
      throw new IOException("String too long: " + bytes.length + " bytes");
    }
    dos.writeShort(bytes.length);
    dos.write(bytes);
  }
}
