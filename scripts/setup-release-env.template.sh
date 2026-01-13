#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# jGuard Release Environment Setup Template
#
# Copy this file to a secure location outside the repo and fill in your credentials:
#   cp scripts/setup-release-env.template.sh ~/keys/jguard/setup-release-env.sh
#   chmod 600 ~/keys/jguard/setup-release-env.sh
#
# Then source it before publishing:
#   source ~/keys/jguard/setup-release-env.sh
#

# ============================================
# GPG Signing
# ============================================
# Export your ASCII-armored private key:
#   gpg --armor --export-secret-keys YOUR_KEY_ID > ~/keys/jguard/release-key.asc
#
# Get your 8-character key ID:
#   gpg --list-secret-keys --keyid-format SHORT

export ORG_GRADLE_PROJECT_signingInMemoryKey="$(cat ~/keys/jguard/release-key.asc)"
export ORG_GRADLE_PROJECT_signingInMemoryKeyId="REPLACE_ME"  # Last 8 chars of key ID
export ORG_GRADLE_PROJECT_signingInMemoryKeyPassword="REPLACE_ME"

# ============================================
# Maven Central (Sonatype Central Portal)
# ============================================
# Generate token at: https://central.sonatype.com/ → View Account → Generate User Token

export ORG_GRADLE_PROJECT_mavenCentralUsername="REPLACE_ME"
export ORG_GRADLE_PROJECT_mavenCentralPassword="REPLACE_ME"

# ============================================
# Gradle Plugin Portal
# ============================================
# Get API keys at: https://plugins.gradle.org/ → API Keys

export GRADLE_PUBLISH_KEY="REPLACE_ME"
export GRADLE_PUBLISH_SECRET="REPLACE_ME"

# ============================================
# Verify Setup
# ============================================
echo "Release environment configured:"
echo "  GPG Key ID: ${ORG_GRADLE_PROJECT_signingInMemoryKeyId}"
echo "  GPG Key: ${ORG_GRADLE_PROJECT_signingInMemoryKey:+set ($(echo "$ORG_GRADLE_PROJECT_signingInMemoryKey" | wc -c | tr -d ' ') bytes)}"
echo "  GPG Password: ${ORG_GRADLE_PROJECT_signingInMemoryKeyPassword:+set}"
echo "  Maven Central Username: ${ORG_GRADLE_PROJECT_mavenCentralUsername:+set}"
echo "  Maven Central Password: ${ORG_GRADLE_PROJECT_mavenCentralPassword:+set}"
echo "  Gradle Publish Key: ${GRADLE_PUBLISH_KEY:+set}"
echo "  Gradle Publish Secret: ${GRADLE_PUBLISH_SECRET:+set}"
