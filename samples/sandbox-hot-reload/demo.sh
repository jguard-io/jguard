#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Automated Hot Reload Demo
#
# This script demonstrates jGuard's hot reload feature with three scenarios:
#
# a. REMOVE an entitlement - shows warning, policy applied
# b. ADD an invalid policy - compilation fails, app continues with old policy (no crash)
# c. ADD valid entitlements - policy applied successfully
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}           jGuard Hot Reload Demo (Automated)${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""
echo "This demo tests three hot reload scenarios:"
echo ""
echo "  a. REMOVE an entitlement"
echo "     - Removes network.outbound from policy"
echo "     - Shows WARNING about removed capability"
echo "     - Policy is applied, network.outbound becomes BLOCKED"
echo ""
echo "  b. ADD an invalid policy (compilation error)"
echo "     - Adds unknown capability 'invalid.capability'"
echo "     - Compilation FAILS"
echo "     - App continues with OLD policy (no crash!)"
echo ""
echo "  c. ADD valid entitlements"
echo "     - Adds env.read and threads.create"
echo "     - Policy applied successfully"
echo "     - New capabilities become ALLOWED"
echo ""

# Save original policy
POLICY_FILE="app/policies-src/io.jguard.samples.hotreload.jguard"
ORIGINAL_POLICY=$(cat "$POLICY_FILE")

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    # Restore original policy
    echo "$ORIGINAL_POLICY" > "$POLICY_FILE"
    # Kill background processes
    if [ -n "$DEMO_PID" ]; then
        kill $DEMO_PID 2>/dev/null || true
        wait $DEMO_PID 2>/dev/null || true
    fi
    # Recompile to restore state
    ../../gradlew :app:compileExternalPolicies -q 2>/dev/null || true
    echo -e "${GREEN}Demo complete. Policy restored to original state.${NC}"
}
trap cleanup EXIT

# Start with a known state: network.outbound enabled, env.read and threads.create disabled
cat > "$POLICY_FILE" << 'EOF'
//
// SPDX-License-Identifier: Apache-2.0
//
security module io.jguard.samples.hotreload {
    entitle module to fs.read("data", "**");
    entitle module to network.outbound;
    entitle module to system.property.read;
}
EOF

echo -e "${YELLOW}Building and compiling initial policy...${NC}"
../../gradlew :app:compileExternalPolicies -q 2>&1

echo ""
echo -e "${YELLOW}Starting application with hot reload enabled...${NC}"
echo "         (Hot reload polls every 2 seconds)"
echo ""

# Start the demo in background
../../gradlew :app:runDemo -q 2>&1 &
DEMO_PID=$!

# Wait for application to start
echo -e "${CYAN}--- Waiting for application to initialize (12 seconds) ---${NC}"
sleep 12

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}  INITIAL STATE:${NC}"
echo -e "${GREEN}    network.outbound ... ALLOWED${NC}"
echo -e "${GREEN}    env.read ........... BLOCKED${NC}"
echo -e "${GREEN}    threads.create ..... BLOCKED${NC}"
echo -e "${GREEN}======================================================================${NC}"

# ============================================================================
# SCENARIO A: REMOVE an entitlement
# ============================================================================
echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  SCENARIO A: REMOVE an entitlement${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""
echo -e "${YELLOW}Modifying policy to REMOVE network.outbound...${NC}"

cat > "$POLICY_FILE" << 'EOF'
//
// SPDX-License-Identifier: Apache-2.0
//
security module io.jguard.samples.hotreload {
    entitle module to fs.read("data", "**");
    // REMOVED: network.outbound
    entitle module to system.property.read;
}
EOF

echo -e "${YELLOW}Recompiling policy...${NC}"
../../gradlew :app:compileExternalPolicies -q 2>&1

echo -e "${CYAN}--- Waiting for hot reload (8 seconds) ---${NC}"
echo -e "${CYAN}    Watch for: WARNING about removed capability${NC}"
sleep 8

echo ""
echo -e "${RED}======================================================================${NC}"
echo -e "${RED}  RESULT A: network.outbound is now BLOCKED${NC}"
echo -e "${RED}            (Warning logged about removed capability)${NC}"
echo -e "${RED}======================================================================${NC}"

# ============================================================================
# SCENARIO B: ADD invalid policy (should fail compilation, app continues)
# ============================================================================
echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  SCENARIO B: ADD invalid policy (compilation error)${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""
echo -e "${YELLOW}Modifying policy to add INVALID capability...${NC}"

cat > "$POLICY_FILE" << 'EOF'
//
// SPDX-License-Identifier: Apache-2.0
//
security module io.jguard.samples.hotreload {
    entitle module to fs.read("data", "**");
    entitle module to system.property.read;
    // INVALID: This capability does not exist!
    entitle module to invalid.capability;
}
EOF

echo -e "${YELLOW}Attempting to compile invalid policy...${NC}"
echo ""
if ../../gradlew :app:compileExternalPolicies -q 2>&1; then
    echo -e "${RED}ERROR: Compilation should have failed!${NC}"
else
    echo ""
    echo -e "${GREEN}Compilation FAILED as expected (invalid capability)${NC}"
fi

echo ""
echo -e "${CYAN}--- Waiting to confirm app still running (6 seconds) ---${NC}"
sleep 6

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}  RESULT B: App continues running with OLD policy${NC}"
echo -e "${GREEN}            (Invalid policy was NOT applied - no crash!)${NC}"
echo -e "${GREEN}            network.outbound is still BLOCKED (from scenario A)${NC}"
echo -e "${GREEN}======================================================================${NC}"

# ============================================================================
# SCENARIO C: ADD valid entitlements
# ============================================================================
echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  SCENARIO C: ADD valid entitlements${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""
echo -e "${YELLOW}Modifying policy to ADD env.read and threads.create...${NC}"

cat > "$POLICY_FILE" << 'EOF'
//
// SPDX-License-Identifier: Apache-2.0
//
security module io.jguard.samples.hotreload {
    entitle module to fs.read("data", "**");
    entitle module to network.outbound;
    entitle module to system.property.read;
    // NEW: Adding env.read and threads.create
    entitle module to env.read;
    entitle module to threads.create;
}
EOF

echo -e "${YELLOW}Recompiling policy...${NC}"
../../gradlew :app:compileExternalPolicies -q 2>&1

echo -e "${CYAN}--- Waiting for hot reload (8 seconds) ---${NC}"
sleep 8

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}  RESULT C: New entitlements applied successfully${NC}"
echo -e "${GREEN}    network.outbound ... ALLOWED${NC}"
echo -e "${GREEN}    env.read ........... ALLOWED${NC}"
echo -e "${GREEN}    threads.create ..... ALLOWED${NC}"
echo -e "${GREEN}======================================================================${NC}"

echo ""
echo -e "${CYAN}--- Running for 10 more seconds to show final state ---${NC}"
sleep 10

echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  DEMO COMPLETE${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""
echo "Summary:"
echo "  a. REMOVE entitlement  -> Warning logged, policy applied"
echo "  b. Invalid policy      -> Compilation failed, app continued (no crash)"
echo "  c. ADD entitlements    -> Policy applied, new capabilities allowed"
echo ""
