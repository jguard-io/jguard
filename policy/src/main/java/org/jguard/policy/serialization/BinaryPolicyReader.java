/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.serialization;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jguard.policy.model.CapabilityArgument;
import org.jguard.policy.model.CapabilityGrant;
import org.jguard.policy.model.Entitlement;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.model.SubjectPattern;

/**
 * Reads a policy descriptor from binary format.
 *
 * <p>See {@link BinaryPolicyWriter} for the binary format specification.
 */
public final class BinaryPolicyReader {

  private static final byte[] MAGIC = {'J', 'G', 'R', 'D'};
  private static final byte FORMAT_VERSION = 1;

  private static final byte SUBJECT_MODULE = 0;
  private static final byte SUBJECT_EXACT = 1;
  private static final byte SUBJECT_DIRECT_CHILDREN = 2;
  private static final byte SUBJECT_RECURSIVE = 3;

  private static final byte ARG_STRING = 0;
  private static final byte ARG_INTEGER = 1;

  private BinaryPolicyReader() {
    // Static utility class
  }

  /** Reads a policy descriptor from a file path. */
  public static PolicyDescriptor fromFile(Path path) throws IOException {
    return fromBytes(Files.readAllBytes(path));
  }

  /** Reads a policy descriptor from a byte array. */
  public static PolicyDescriptor fromBytes(byte[] bytes) throws IOException {
    return read(new ByteArrayInputStream(bytes));
  }

  /** Reads a policy descriptor from an input stream. */
  public static PolicyDescriptor read(InputStream in) throws IOException {
    DataInputStream dis = new DataInputStream(in);

    // Read and validate magic bytes
    byte[] magic = new byte[4];
    dis.readFully(magic);
    if (magic[0] != MAGIC[0]
        || magic[1] != MAGIC[1]
        || magic[2] != MAGIC[2]
        || magic[3] != MAGIC[3]) {
      throw new IOException(
          "Invalid policy file: expected JGRD magic bytes, got "
              + new String(magic, StandardCharsets.US_ASCII));
    }

    // Read and validate version
    byte version = dis.readByte();
    if (version != FORMAT_VERSION) {
      throw new IOException("Unsupported policy format version: " + version);
    }

    // Read module name
    String moduleName = readString(dis);

    // Read entitlements
    int entitlementCount = dis.readUnsignedShort();
    List<Entitlement> entitlements = new ArrayList<>(entitlementCount);

    for (int i = 0; i < entitlementCount; i++) {
      entitlements.add(readEntitlement(dis));
    }

    return new PolicyDescriptor(FORMAT_VERSION, moduleName, entitlements);
  }

  private static Entitlement readEntitlement(DataInputStream dis) throws IOException {
    // Read subject type
    byte subjectTypeByte = dis.readByte();
    SubjectPattern.Type subjectType =
        switch (subjectTypeByte) {
          case SUBJECT_MODULE -> SubjectPattern.Type.MODULE;
          case SUBJECT_EXACT -> SubjectPattern.Type.PACKAGE_EXACT;
          case SUBJECT_DIRECT_CHILDREN -> SubjectPattern.Type.PACKAGE_DIRECT_CHILDREN;
          case SUBJECT_RECURSIVE -> SubjectPattern.Type.PACKAGE_RECURSIVE;
          default -> throw new IOException("Unknown subject type: " + subjectTypeByte);
        };

    // Read package name (if not module)
    String packageName = null;
    if (subjectType != SubjectPattern.Type.MODULE) {
      packageName = readString(dis);
    }

    SubjectPattern subject = new SubjectPattern(subjectType, packageName);

    // Read capability name
    String capabilityName = readString(dis);

    // Read arguments
    int argCount = dis.readUnsignedByte();
    List<CapabilityArgument> arguments = new ArrayList<>(argCount);

    for (int i = 0; i < argCount; i++) {
      arguments.add(readArgument(dis));
    }

    CapabilityGrant capability = new CapabilityGrant(capabilityName, arguments);

    return new Entitlement(subject, capability);
  }

  private static CapabilityArgument readArgument(DataInputStream dis) throws IOException {
    byte type = dis.readByte();
    return switch (type) {
      case ARG_STRING -> new CapabilityArgument.StringArg(readString(dis));
      case ARG_INTEGER -> new CapabilityArgument.IntegerArg(dis.readLong());
      default -> throw new IOException("Unknown argument type: " + type);
    };
  }

  private static String readString(DataInputStream dis) throws IOException {
    int length = dis.readUnsignedShort();
    byte[] bytes = new byte[length];
    dis.readFully(bytes);
    return new String(bytes, StandardCharsets.UTF_8);
  }
}
