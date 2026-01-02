/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.serialization;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import org.jguard.policy.model.CapabilityArgument;
import org.jguard.policy.model.CapabilityGrant;
import org.jguard.policy.model.Entitlement;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.model.SubjectPattern;

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
  private static final byte FORMAT_VERSION = 1;

  private static final byte SUBJECT_MODULE = 0;
  private static final byte SUBJECT_EXACT = 1;
  private static final byte SUBJECT_DIRECT_CHILDREN = 2;
  private static final byte SUBJECT_RECURSIVE = 3;

  private static final byte ARG_STRING = 0;
  private static final byte ARG_INTEGER = 1;

  private BinaryPolicyWriter() {
    // Static utility class
  }

  /**
   * Writes a policy descriptor to a byte array.
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
   * Writes a policy descriptor to an output stream.
   *
   * @param policy the policy descriptor to write
   * @param out the output stream to write to
   * @throws IOException if an I/O error occurs
   */
  public static void write(PolicyDescriptor policy, OutputStream out) throws IOException {
    DataOutputStream dos = new DataOutputStream(out);

    // Header
    dos.write(MAGIC);
    dos.writeByte(FORMAT_VERSION);

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
