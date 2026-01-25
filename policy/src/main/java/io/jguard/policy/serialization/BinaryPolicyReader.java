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
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads a policy descriptor from binary format.
 *
 * <p>See {@link BinaryPolicyWriter} for the binary format specification.
 */
public final class BinaryPolicyReader {

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

  private BinaryPolicyReader() {
    // Static utility class
  }

  // ========== ApplicationPolicy (V1 or V2) ==========

  /**
   * Reads an application policy from a file path.
   *
   * <p>Supports both v1 (single-module) and v2 (multi-module) formats. V1 files are automatically
   * wrapped into an ApplicationPolicy with a single module.
   *
   * @param path the path to the policy file
   * @return the deserialized application policy
   * @throws IOException if an I/O error occurs
   */
  public static ApplicationPolicy applicationPolicyFromFile(Path path) throws IOException {
    return applicationPolicyFromBytes(Files.readAllBytes(path));
  }

  /**
   * Reads an application policy from a byte array.
   *
   * <p>Supports both v1 (single-module) and v2 (multi-module) formats.
   *
   * @param bytes the serialized policy bytes
   * @return the deserialized application policy
   * @throws IOException if an I/O error occurs
   */
  public static ApplicationPolicy applicationPolicyFromBytes(byte[] bytes) throws IOException {
    return readApplicationPolicy(new ByteArrayInputStream(bytes));
  }

  /**
   * Reads an application policy from an input stream.
   *
   * <p>Supports both v1 (single-module) and v2 (multi-module) formats. V1 files are automatically
   * wrapped into an ApplicationPolicy with a single module.
   *
   * @param in the input stream to read from
   * @return the deserialized application policy
   * @throws IOException if an I/O error occurs
   */
  public static ApplicationPolicy readApplicationPolicy(InputStream in) throws IOException {
    DataInputStream dis = new DataInputStream(in);

    // Read and validate magic bytes
    byte[] magic = new byte[4];
    dis.readFully(magic);
    validateMagic(magic);

    // Read version and dispatch to appropriate reader
    byte version = dis.readByte();
    return switch (version) {
      case FORMAT_VERSION_V1 -> readV1AsApplicationPolicy(dis);
      case FORMAT_VERSION_V2 -> readV2ApplicationPolicy(dis);
      case FORMAT_VERSION_V3 -> readV3ApplicationPolicy(dis);
      default -> throw new IOException("Unsupported policy format version: " + version);
    };
  }

  private static ApplicationPolicy readV1AsApplicationPolicy(DataInputStream dis)
      throws IOException {
    // V1 format: single module
    String moduleName = readString(dis);
    List<Entitlement> entitlements = readEntitlements(dis);
    ModulePolicy module = new ModulePolicy(moduleName, entitlements);
    return ApplicationPolicy.single(module);
  }

  private static ApplicationPolicy readV2ApplicationPolicy(DataInputStream dis) throws IOException {
    // V2 format: multiple modules (no trusted flag)
    int moduleCount = dis.readUnsignedShort();
    List<ModulePolicy> modules = new ArrayList<>(moduleCount);

    for (int i = 0; i < moduleCount; i++) {
      modules.add(readModuleV2(dis));
    }

    return new ApplicationPolicy(ApplicationPolicy.FORMAT_VERSION, modules);
  }

  private static ApplicationPolicy readV3ApplicationPolicy(DataInputStream dis) throws IOException {
    // V3 format: multiple modules with trusted flag
    int moduleCount = dis.readUnsignedShort();
    List<ModulePolicy> modules = new ArrayList<>(moduleCount);

    for (int i = 0; i < moduleCount; i++) {
      modules.add(readModuleV3(dis));
    }

    return new ApplicationPolicy(ApplicationPolicy.FORMAT_VERSION, modules);
  }

  private static ModulePolicy readModuleV2(DataInputStream dis) throws IOException {
    String moduleName = readString(dis);
    List<Entitlement> entitlements = readEntitlements(dis);
    List<Denial> denials = readDenials(dis);
    return new ModulePolicy(moduleName, entitlements, denials, false);
  }

  private static ModulePolicy readModuleV3(DataInputStream dis) throws IOException {
    String moduleName = readString(dis);
    boolean trusted = dis.readByte() != 0;
    List<Entitlement> entitlements = readEntitlements(dis);
    List<Denial> denials = readDenials(dis);
    return new ModulePolicy(moduleName, entitlements, denials, trusted);
  }

  private static List<Entitlement> readEntitlements(DataInputStream dis) throws IOException {
    int entitlementCount = dis.readUnsignedShort();
    List<Entitlement> entitlements = new ArrayList<>(entitlementCount);
    for (int i = 0; i < entitlementCount; i++) {
      entitlements.add(readEntitlement(dis));
    }
    return entitlements;
  }

  private static List<Denial> readDenials(DataInputStream dis) throws IOException {
    int denialCount = dis.readUnsignedShort();
    List<Denial> denials = new ArrayList<>(denialCount);
    for (int i = 0; i < denialCount; i++) {
      denials.add(readDenial(dis));
    }
    return denials;
  }

  // ========== PolicyDescriptor (V1 Legacy) ==========

  /**
   * Reads a policy descriptor from a file path.
   *
   * <p>This method only supports v1 format. For v2 support, use {@link
   * #applicationPolicyFromFile(Path)}.
   *
   * @param path the path to the policy file
   * @return the deserialized policy descriptor
   * @throws IOException if an I/O error occurs
   */
  public static PolicyDescriptor fromFile(Path path) throws IOException {
    return fromBytes(Files.readAllBytes(path));
  }

  /**
   * Reads a policy descriptor from a byte array.
   *
   * <p>This method only supports v1 format. For v2 support, use {@link
   * #applicationPolicyFromBytes(byte[])}.
   *
   * @param bytes the serialized policy bytes
   * @return the deserialized policy descriptor
   * @throws IOException if an I/O error occurs
   */
  public static PolicyDescriptor fromBytes(byte[] bytes) throws IOException {
    return read(new ByteArrayInputStream(bytes));
  }

  /**
   * Reads a policy descriptor from an input stream.
   *
   * <p>This method only supports v1 format. For v2 support, use {@link
   * #readApplicationPolicy(InputStream)}.
   *
   * @param in the input stream to read from
   * @return the deserialized policy descriptor
   * @throws IOException if an I/O error occurs
   */
  public static PolicyDescriptor read(InputStream in) throws IOException {
    DataInputStream dis = new DataInputStream(in);

    // Read and validate magic bytes
    byte[] magic = new byte[4];
    dis.readFully(magic);
    validateMagic(magic);

    // Read and validate version (v1 only for PolicyDescriptor)
    byte version = dis.readByte();
    if (version != FORMAT_VERSION_V1) {
      throw new IOException(
          "PolicyDescriptor only supports v1 format. Use readApplicationPolicy() for v2. "
              + "Got version: "
              + version);
    }

    // Read module name
    String moduleName = readString(dis);

    // Read entitlements
    List<Entitlement> entitlements = readEntitlements(dis);

    return new PolicyDescriptor(FORMAT_VERSION_V1, moduleName, entitlements);
  }

  // ========== Common Helpers ==========

  private static void validateMagic(byte[] magic) throws IOException {
    if (magic[0] != MAGIC[0]
        || magic[1] != MAGIC[1]
        || magic[2] != MAGIC[2]
        || magic[3] != MAGIC[3]) {
      throw new IOException(
          "Invalid policy file: expected JGRD magic bytes, got "
              + new String(magic, StandardCharsets.US_ASCII));
    }
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

  private static Denial readDenial(DataInputStream dis) throws IOException {
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

    // Read defensive flag
    byte defensiveByte = dis.readByte();
    boolean defensive = (defensiveByte != 0);

    return new Denial(subject, capability, defensive);
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
