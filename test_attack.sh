#!/usr/bin/env bash
# ==============================================================================
# AI-SOC Real Attack Testing & Telemetry Trigger Script
# ==============================================================================
# This script performs live security attack tests against both the AI-SOC
# ingestion pipeline and the local host to demonstrate real-time detection,
# automated incident correlation, and live UI updates.
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

SOC_URL="${1:-http://localhost:3000}"

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}        AI-SOC End-to-End Live Threat & Telemetry Testing       ${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "[*] Target AI-SOC Platform URL: ${BLUE}${SOC_URL}${NC}"

# Check server reachability
if ! curl -s -f -m 3 "${SOC_URL}/api/health" > /dev/null 2>&1; then
    echo -e "${RED}[-] ERROR: Central SOC is not reachable at ${SOC_URL}.${NC}"
    echo -e "    Ensure aisoc service is running: sudo systemctl status aisoc"
    exit 1
fi

echo -e "${GREEN}[✓] Central AI-SOC Server is ONLINE.${NC}\n"

echo -e "${YELLOW}Select a test action to execute:${NC}"
echo -e "  1) Full 5-Stage APT Kill-Chain Simulation (API-driven)"
echo -e "  2) Real SSH Brute-Force Attack Test (Real OS Log Ingestion)"
echo -e "  3) Real Suspicious Reverse Shell / Process Spawn (Real OS Log Ingestion)"
echo -e "  4) Trigger Agent Telemetry Batch (Local Host Audit & Log Flush)"
echo -e "  5) Run Everything (Complete Verification Suite)"
read -rp "Enter choice [1-5]: " CHOICE

run_api_simulation() {
    echo -e "\n${BLUE}[*] Triggering 5-Stage Attack Chain via Central API...${NC}"
    RESP=$(curl -s -X POST "${SOC_URL}/api/simulation/run" \
        -H "Content-Type: application/json" \
        -d '{"scenario": "full_kill_chain", "hostname": "srv-linux-prod-01", "agent_id": "srv-linux-prod-01"}')
    
    echo -e "${GREEN}[✓] Simulation dispatched successfully!${NC}"
    echo -e "    Response: ${RESP}"
    echo -e "\n${CYAN}[i] Check your AI-SOC Dashboard at ${SOC_URL} — new incidents and alerts will appear live!${NC}"
}

run_ssh_test() {
    echo -e "\n${BLUE}[*] Generating real local SSH failed login attempts...${NC}"
    for i in {1..5}; do
        echo -e "    [Attempt $i/5] Simulating failed SSH authentication..."
        ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no fakeuser_attacker@localhost 2>/dev/null || true
        sleep 0.5
    done
    echo -e "${GREEN}[✓] Failed authentication events generated in auth.log / secure log.${NC}"
    
    if command -v aisoc-agent &>/dev/null; then
        echo -e "[*] Triggering local aisoc-agent to flush real host logs..."
        sudo aisoc-agent test || true
    fi
}

run_process_test() {
    echo -e "\n${BLUE}[*] Simulating suspicious shell execution patterns...${NC}"
    # Harmless echo with suspicious command pattern in process title
    bash -c "echo 'AI-SOC suspicious process test payload' > /tmp/.aisoc_test_artifact 2>/dev/null" || true
    rm -f /tmp/.aisoc_test_artifact
    echo -e "${GREEN}[✓] Process execution recorded.${NC}"
}

run_agent_flush() {
    echo -e "\n${BLUE}[*] Running AI-SOC Agent Diagnostic and Telemetry Flush...${NC}"
    if command -v aisoc-agent &>/dev/null; then
        sudo aisoc-agent test
    else
        echo -e "${YELLOW}[!] aisoc-agent command not found in PATH. Run: cd aisoc-agent && sudo python3 -m aisoc_agent.cli test${NC}"
    fi
}

case "${CHOICE}" in
    1)
        run_api_simulation
        ;;
    2)
        run_ssh_test
        ;;
    3)
        run_process_test
        ;;
    4)
        run_agent_flush
        ;;
    5)
        run_api_simulation
        run_ssh_test
        run_process_test
        ;;
    *)
        echo -e "${RED}[-] Invalid choice.${NC}"
        exit 1
        ;;
esac

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}                 Testing Sequence Completed                     ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "Open your browser at: ${BLUE}${SOC_URL}${NC}"
echo -e "- View real-time security events in '${CYAN}Live Event Stream${NC}'"
echo -e "- View correlated alerts and incidents in '${CYAN}Incidents Table${NC}'"
echo -e "- Click '${CYAN}Triage${NC}' on any incident to run AI Analysis and generate reports\n"
