#!/usr/bin/env bash
# OpenShell cleanup script for OpenShift
# Removes OpenShell deployment and optionally custom SCC

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NAMESPACE="${OPENSHELL_NAMESPACE:-openshell}"
GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-openshift}"

# Validate inputs to prevent path traversal (CWE-22)
if [[ ! "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "ERROR: Invalid namespace name. Must match Kubernetes naming conventions." >&2
    exit 1
fi

# Enforce Kubernetes DNS label length limit (63 characters)
if [[ ${#NAMESPACE} -gt 63 ]]; then
    echo "ERROR: Namespace name too long (${#NAMESPACE} chars). Maximum is 63 characters." >&2
    exit 1
fi

# Reject protected OpenShift/Kubernetes system namespaces
case "$NAMESPACE" in
    default|kube-*|openshift-*|kubernetes-dashboard)
        echo "ERROR: Cannot delete protected system namespace: $NAMESPACE" >&2
        echo "This script only cleans up namespaces it created." >&2
        exit 1
        ;;
esac

if [[ ! "$GATEWAY_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "ERROR: Invalid gateway name. Must be alphanumeric with dots, underscores, or hyphens." >&2
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
    echo -e "${BLUE}==>${NC} $*"
}

echo "=========================================="
echo "  OpenShell Cleanup"
echo "=========================================="
echo ""

log_warn "This will delete the OpenShell deployment from the ${NAMESPACE} namespace"
read -p "Are you sure you want to continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Cleanup cancelled"
    exit 0
fi

# Delete all sandboxes BEFORE removing gateway configuration
if command -v openshell &> /dev/null && command -v oc &> /dev/null; then
    log_step "Deleting all sandboxes..."
    # Guard sandbox listing to prevent script termination on failure
    if sandbox_list=$(openshell sandbox list --gateway "${GATEWAY_NAME}" 2>/dev/null); then
        echo "$sandbox_list" | tail -n +2 | awk '{print $1}' | while read -r sandbox; do
            if [[ -n "$sandbox" ]]; then
                log_info "Deleting sandbox: ${sandbox}"
                openshell sandbox delete "${sandbox}" 2>/dev/null || log_warn "Failed to delete sandbox: ${sandbox}"
            fi
        done
    else
        log_warn "Could not list sandboxes for gateway '${GATEWAY_NAME}'"
    fi
fi

# Force-delete Sandbox CRs if CLI deletion failed
if command -v oc &> /dev/null; then
    log_step "Cleaning up any remaining Sandbox custom resources..."
    if oc get sandboxes -n "${NAMESPACE}" &> /dev/null; then
        while IFS= read -r sandbox; do
            if [[ -n "$sandbox" ]]; then
                log_info "Force-deleting Sandbox CR: ${sandbox}"
                # Try normal deletion first
                if ! oc delete "${sandbox}" -n "${NAMESPACE}" --timeout=30s 2>/dev/null; then
                    # If stuck (likely due to finalizers), patch to remove finalizers
                    log_warn "Sandbox CR stuck, removing finalizers: ${sandbox}"
                    oc patch "${sandbox}" -n "${NAMESPACE}" -p '{"metadata":{"finalizers":null}}' --type=merge 2>/dev/null || true
                fi
            fi
        done < <(oc get sandboxes -n "${NAMESPACE}" -o name 2>/dev/null)
    fi
fi

# Clean up OpenShell CLI configuration
if command -v openshell &> /dev/null; then
    log_step "Cleaning up OpenShell CLI configuration..."

    # Delete all providers
    if provider_list=$(openshell provider list --gateway "${GATEWAY_NAME}" 2>/dev/null); then
        echo "$provider_list" | tail -n +2 | awk '{print $1}' | while read -r provider; do
            if [[ -n "$provider" ]]; then
                log_info "Deleting provider: ${provider}"
                openshell provider delete "${provider}" --gateway "${GATEWAY_NAME}" 2>/dev/null || log_warn "Failed to delete provider: ${provider}"
            fi
        done
    fi

    # Reset inference configuration
    log_info "Resetting inference configuration..."
    openshell inference unset --gateway "${GATEWAY_NAME}" 2>/dev/null || true

    # Unset global settings
    log_info "Unsetting global settings..."
    openshell settings unset --global --key providers_v2_enabled 2>/dev/null || true
fi

# Now remove gateway from CLI (after sandboxes are deleted)
if command -v openshell &> /dev/null; then
    log_step "Removing gateway '${GATEWAY_NAME}' from openshell CLI..."
    openshell gateway remove "${GATEWAY_NAME}" 2>/dev/null || log_warn "Gateway '${GATEWAY_NAME}' not found in CLI"

    # Remove local certificates
    log_step "Removing local certificates..."
    rm -rf -- "${HOME}/.config/openshell/gateways/${GATEWAY_NAME}" 2>/dev/null || true
fi

# Delete Route
if command -v oc &> /dev/null; then
    log_step "Deleting OpenShift route..."
    oc delete route openshell -n "${NAMESPACE}" --ignore-not-found=true
fi

# Uninstall Helm chart
if command -v helm &> /dev/null; then
    log_step "Uninstalling OpenShell Helm chart..."
    helm uninstall openshell -n "${NAMESPACE}" 2>/dev/null || log_warn "Helm release 'openshell' not found"
fi

# Remove SCC bindings
if command -v oc &> /dev/null; then
    log_step "Removing SCC bindings..."
    oc adm policy remove-scc-from-user privileged -z openshell-sandbox -n "${NAMESPACE}" 2>/dev/null || true
    oc adm policy remove-scc-from-user openshell-sandbox-minimum-required -z openshell-sandbox -n "${NAMESPACE}" 2>/dev/null || true
    oc adm policy remove-scc-from-user restricted-v2 -z openshell-sandbox -n "${NAMESPACE}" 2>/dev/null || true
    oc adm policy remove-scc-from-user restricted-v2 -z openshell-certgen -n "${NAMESPACE}" 2>/dev/null || true
fi

# Delete namespace (this cascades to all resources)
if command -v oc &> /dev/null; then
    log_step "Deleting namespace ${NAMESPACE}..."
    if ! oc delete namespace "${NAMESPACE}" --ignore-not-found=true --timeout=60s 2>&1; then
        log_warn "Namespace deletion timed out, checking if stuck in Terminating state..."

        # Check if namespace is stuck terminating
        if oc get namespace "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q "Terminating"; then
            log_warn "Namespace is stuck in Terminating state, attempting to force cleanup..."

            # Remove finalizers from any remaining resources
            for resource_type in sandboxes configmaps secrets services deployments; do
                while IFS= read -r resource; do
                    if [[ -n "$resource" ]]; then
                        log_info "Removing finalizers from ${resource}"
                        oc patch "${resource}" -n "${NAMESPACE}" -p '{"metadata":{"finalizers":null}}' --type=merge 2>/dev/null || true
                    fi
                done < <(oc get "${resource_type}" -n "${NAMESPACE}" -o name 2>/dev/null)
            done

            # Wait a bit for namespace to finish deleting
            log_info "Waiting for namespace deletion to complete..."
            for i in {1..30}; do
                if ! oc get namespace "${NAMESPACE}" &> /dev/null; then
                    log_info "Namespace ${NAMESPACE} deleted successfully"
                    break
                fi
                sleep 2
            done

            # Final check
            if oc get namespace "${NAMESPACE}" &> /dev/null; then
                log_error "Namespace still exists after forced cleanup"
                log_warn "Manual intervention required. Check with: oc get namespace ${NAMESPACE} -o yaml"
                exit 1
            fi
        else
            log_error "Namespace deletion failed"
            exit 1
        fi
    else
        log_info "Namespace ${NAMESPACE} deleted successfully"
    fi
else
    log_error "oc command not found - cannot delete namespace"
    exit 1
fi

log_info "OpenShell deployment cleaned up!"
echo ""

# Note about custom SCC (cluster-scoped resource)
echo ""
log_warn "Note: The custom SCC 'openshell-sandbox-minimum-required' was NOT removed."
log_warn "This is a cluster-scoped resource that may be used by other namespaces."
log_warn ""
log_warn "To safely remove it, verify it's not in use elsewhere:"
log_warn "  1. Check for other bindings: oc get clusterrolebindings -o yaml | grep openshell-sandbox-minimum-required"
log_warn "  2. Check which ServiceAccounts use it: oc get scc openshell-sandbox-minimum-required -o yaml"
log_warn "  3. Only delete if unused: oc delete scc openshell-sandbox-minimum-required"
echo ""

# Note about Agent Sandbox (cluster-scoped resource)
echo ""
log_warn "Note: Agent Sandbox CRDs and cluster resources were NOT removed."
log_warn "Agent Sandbox is a cluster-scoped operator that may be used by other namespaces."
log_warn ""
log_warn "To safely remove Agent Sandbox, first verify it's not in use elsewhere:"
log_warn "  1. Check for Sandbox instances in other namespaces:"
log_warn "     oc get sandboxes --all-namespaces"
log_warn "  2. List all Agent Sandbox CRDs:"
log_warn "     oc get crd | grep sandbox"
log_warn "  3. If no other namespaces use it, uninstall via:"
log_warn "     - OpenShift Console: Operators → Installed Operators → Uninstall Agent Sandbox Operator"
log_warn "     - Or manually with the SAME version you installed"
echo ""

log_info "Cleanup complete!"
