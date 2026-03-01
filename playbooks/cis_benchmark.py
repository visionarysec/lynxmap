"""
LynxMap — CIS OCI Foundations Benchmark Runner
Implements automated CIS benchmark checks against live OCI tenancy.
Modeled after Trend Micro Conformity / CIS Compliance Script.

Categories:
  1. Identity & Access Management (IAM)
  2. Networking
  3. Storage (Object Storage, Block Volumes)
  4. Compute
  5. Logging & Monitoring
  6. Database
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class CISCheckResult:
    """Result of a single CIS benchmark check."""
    check_id: str                # e.g. "CIS-1.1"
    title: str
    category: str                # e.g. "Identity & Access Management"
    severity: str                # critical, high, medium, low, informational
    status: str                  # "PASS", "FAIL", "ERROR", "SKIPPED"
    affected_resources: List[str] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    cis_section: str = ""        # e.g. "1.1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "affected_resources": self.affected_resources,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cis_section": self.cis_section,
        }


@dataclass
class CISBenchmarkReport:
    """Full CIS benchmark report."""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    scan_mode: str = "live"       # "live" or "mock"
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    results: List[CISCheckResult] = field(default_factory=list)
    region: str = ""
    tenancy_name: str = ""

    @property
    def compliance_pct(self) -> float:
        evaluated = self.passed + self.failed
        if evaluated == 0:
            return 0.0
        return round(100.0 * self.passed / evaluated, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_mode": self.scan_mode,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "compliance_pct": self.compliance_pct,
            "region": self.region,
            "tenancy_name": self.tenancy_name,
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# CIS Benchmark Runner
# ---------------------------------------------------------------------------
class CISBenchmarkRunner:
    """
    Runs CIS OCI Foundations Benchmark checks against a live OCI tenancy.
    Uses OCICollector for data gathering and implements each check as a
    dedicated method.
    """

    def __init__(self, collector=None, progress_callback=None):
        self.collector = collector
        self.progress_callback = progress_callback

    def _progress(self, msg: str):
        logger.info(msg)
        if self.progress_callback:
            try:
                self.progress_callback(msg)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def run(self) -> CISBenchmarkReport:
        """Run all CIS benchmark checks and return a report."""
        report = CISBenchmarkReport()

        if self.collector and self.collector.config:
            report.scan_mode = "live"
            report.region = self.collector.config.get("region", "unknown")
            self._run_live(report)
        else:
            report.scan_mode = "mock"
            self._run_mock(report)

        report.completed_at = datetime.now()
        # Tally
        for r in report.results:
            if r.status == "PASS":
                report.passed += 1
            elif r.status == "FAIL":
                report.failed += 1
            elif r.status == "ERROR":
                report.errors += 1
            else:
                report.skipped += 1
        report.total_checks = len(report.results)
        return report

    # ------------------------------------------------------------------
    # Live scanning
    # ------------------------------------------------------------------
    def _run_live(self, report: CISBenchmarkReport):
        """Run checks against real OCI tenancy."""
        try:
            self._progress("CIS Benchmark: Collecting OCI data…")

            identity = self.collector.clients.get("identity")
            network = self.collector.clients.get("network")
            compute = self.collector.clients.get("compute")
            objstore = self.collector.clients.get("object_storage")
            tenancy_id = self.collector.config["tenancy"]

            # Ensure compartments are loaded
            if not self.collector.compartments:
                self.collector.compartments = (
                    self.collector._collect_compartment_details()
                )

            active_comps = [
                c for c in self.collector.compartments
                if c.get("lifecycle_state") == "ACTIVE"
            ]

            # ── 1. IAM Checks ──────────────────────────────────────────
            self._progress("CIS Benchmark: Running IAM checks…")
            if identity:
                self._check_iam(identity, tenancy_id, active_comps, report)

            # ── 2. Networking Checks ───────────────────────────────────
            self._progress("CIS Benchmark: Running Networking checks…")
            if network:
                self._check_networking(network, active_comps, report)

            # ── 3. Storage Checks ──────────────────────────────────────
            self._progress("CIS Benchmark: Running Storage checks…")
            if objstore:
                self._check_storage(objstore, active_comps, report)

            # ── 4. Compute Checks ──────────────────────────────────────
            self._progress("CIS Benchmark: Running Compute checks…")
            if compute and network:
                self._check_compute(compute, network, active_comps, report)

            # ── 5. Logging & Monitoring ────────────────────────────────
            self._progress("CIS Benchmark: Running Logging checks…")
            self._check_logging(tenancy_id, report)

            self._progress("CIS Benchmark: Complete!")

        except Exception as e:
            logger.error("CIS Benchmark live scan error: %s", e)

    # ==================================================================
    # SECTION 1: Identity & Access Management
    # ==================================================================
    def _check_iam(self, identity, tenancy_id, compartments, report):
        """Run all IAM-related CIS checks."""

        # ── CIS 1.1: MFA for console users ───────────────────────────
        try:
            users = identity.list_users(tenancy_id).data
            console_users = [
                u for u in users
                if getattr(u, "can_use_console_password", True)
            ]
            no_mfa = [
                u.name for u in console_users
                if not getattr(u, "is_mfa_activated", False)
            ]
            report.results.append(CISCheckResult(
                check_id="CIS-1.1",
                title="Ensure MFA is enabled for all users with console password",
                category="Identity & Access Management",
                severity="critical",
                status="FAIL" if no_mfa else "PASS",
                affected_resources=no_mfa[:20],
                evidence=(
                    f"{len(no_mfa)} user(s) without MFA"
                    if no_mfa else "All console users have MFA enabled"
                ),
                remediation="Enable MFA: Identity > Users > [User] > Enable MFA",
                cis_section="1.1",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.1",
                title="Ensure MFA is enabled for all users with console password",
                category="Identity & Access Management",
                severity="critical",
                status="ERROR",
                evidence=str(e),
                cis_section="1.1",
            ))

        # ── CIS 1.2: API key rotation (90 days) ────────────────────
        try:
            stale_keys = []
            cutoff = datetime.utcnow() - timedelta(days=90)
            for user in users:
                try:
                    api_keys = identity.list_api_keys(user.id).data
                    for key in api_keys:
                        created = key.time_created
                        if hasattr(created, 'replace'):
                            created = created.replace(tzinfo=None)
                        if created < cutoff:
                            stale_keys.append(
                                f"{user.name} (key: {key.fingerprint[-8:]}…)"
                            )
                except Exception:
                    pass

            report.results.append(CISCheckResult(
                check_id="CIS-1.2",
                title="Ensure API keys are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if stale_keys else "PASS",
                affected_resources=stale_keys[:20],
                evidence=(
                    f"{len(stale_keys)} stale API key(s) older than 90 days"
                    if stale_keys
                    else "All API keys rotated within 90 days"
                ),
                remediation="Rotate API keys: Identity > Users > [User] > API Keys",
                cis_section="1.2",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.2",
                title="Ensure API keys are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="ERROR",
                evidence=str(e),
                cis_section="1.2",
            ))

        # ── CIS 1.3: No API keys for tenancy admins ──────────────────
        try:
            admin_group = None
            groups = identity.list_groups(tenancy_id).data
            for g in groups:
                if g.name.lower() == "administrators":
                    admin_group = g
                    break

            admin_with_keys = []
            if admin_group:
                memberships = identity.list_user_group_memberships(
                    tenancy_id, group_id=admin_group.id
                ).data
                admin_user_ids = {m.user_id for m in memberships}
                for user in users:
                    if user.id in admin_user_ids:
                        try:
                            keys = identity.list_api_keys(user.id).data
                            if keys:
                                admin_with_keys.append(user.name)
                        except Exception:
                            pass

            report.results.append(CISCheckResult(
                check_id="CIS-1.3",
                title="Ensure no API keys exist for tenancy administrator users",
                category="Identity & Access Management",
                severity="critical",
                status="FAIL" if admin_with_keys else "PASS",
                affected_resources=admin_with_keys,
                evidence=(
                    f"{len(admin_with_keys)} admin(s) with API keys"
                    if admin_with_keys
                    else "No administrator users have API keys"
                ),
                remediation="Remove API keys from administrator accounts",
                cis_section="1.3",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.3",
                title="Ensure no API keys exist for tenancy administrator users",
                category="Identity & Access Management",
                severity="critical",
                status="ERROR",
                evidence=str(e),
                cis_section="1.3",
            ))

        # ── CIS 1.4: Auth token rotation (90 days) ──────────────────
        try:
            stale_tokens = []
            for user in users:
                try:
                    tokens = identity.list_auth_tokens(user.id).data
                    for tok in tokens:
                        created = tok.time_created
                        if hasattr(created, 'replace'):
                            created = created.replace(tzinfo=None)
                        if created < cutoff:
                            stale_tokens.append(user.name)
                except Exception:
                    pass

            report.results.append(CISCheckResult(
                check_id="CIS-1.4",
                title="Ensure auth tokens are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if stale_tokens else "PASS",
                affected_resources=list(set(stale_tokens))[:20],
                evidence=(
                    f"{len(stale_tokens)} stale auth token(s)"
                    if stale_tokens
                    else "All auth tokens rotated within 90 days"
                ),
                remediation="Rotate auth tokens: Identity > Users > [User] > Auth Tokens",
                cis_section="1.4",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.4",
                title="Ensure auth tokens are rotated within 90 days",
                category="Identity & Access Management",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="1.4",
            ))

        # ── CIS 1.5: Overly permissive policies ──────────────────────
        try:
            overly_permissive = []
            policies = identity.list_policies(tenancy_id).data
            danger_patterns = [
                "manage all-resources",
                "use all-resources",
            ]
            for pol in policies:
                for stmt in (pol.statements or []):
                    lower = stmt.lower()
                    for pat in danger_patterns:
                        if pat in lower and "administrators" not in lower:
                            overly_permissive.append(
                                f"{pol.name}: {stmt[:80]}…"
                            )

            report.results.append(CISCheckResult(
                check_id="CIS-1.5",
                title="Ensure IAM policies do not grant overly broad permissions",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if overly_permissive else "PASS",
                affected_resources=overly_permissive[:20],
                evidence=(
                    f"{len(overly_permissive)} overly permissive statement(s)"
                    if overly_permissive
                    else "No overly permissive policy statements found"
                ),
                remediation="Restrict policies to least-privilege using specific resource types",
                cis_section="1.5",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.5",
                title="Ensure IAM policies do not grant overly broad permissions",
                category="Identity & Access Management",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="1.5",
            ))

        # ── CIS 1.6: Inactive users (no login > 90 days) ─────────────
        try:
            inactive = []
            for user in users:
                last_login = getattr(user, "last_successful_login_time", None)
                created = user.time_created
                if hasattr(created, 'replace'):
                    created = created.replace(tzinfo=None)
                if last_login:
                    if hasattr(last_login, 'replace'):
                        last_login = last_login.replace(tzinfo=None)
                    if last_login < cutoff:
                        inactive.append(user.name)
                elif created < cutoff:
                    # Never logged in and created > 90 days ago
                    inactive.append(f"{user.name} (never logged in)")

            report.results.append(CISCheckResult(
                check_id="CIS-1.6",
                title="Ensure users inactive for 90+ days are disabled",
                category="Identity & Access Management",
                severity="medium",
                status="FAIL" if inactive else "PASS",
                affected_resources=inactive[:20],
                evidence=(
                    f"{len(inactive)} inactive user(s)"
                    if inactive else "No inactive users found"
                ),
                remediation="Disable or remove users inactive > 90 days",
                cis_section="1.6",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.6",
                title="Ensure users inactive for 90+ days are disabled",
                category="Identity & Access Management",
                severity="medium",
                status="ERROR", evidence=str(e), cis_section="1.6",
            ))

        # ── CIS 1.7: Password policy strength ────────────────────────
        try:
            auth_policy = identity.get_authentication_policy(tenancy_id).data
            pwd = auth_policy.password_policy
            issues = []
            if pwd:
                if pwd.minimum_password_length and pwd.minimum_password_length < 14:
                    issues.append(f"Min length {pwd.minimum_password_length} (should be ≥14)")
                if not getattr(pwd, "is_uppercase_characters_required", True):
                    issues.append("Uppercase not required")
                if not getattr(pwd, "is_lowercase_characters_required", True):
                    issues.append("Lowercase not required")
                if not getattr(pwd, "is_numeric_characters_required", True):
                    issues.append("Numbers not required")
                if not getattr(pwd, "is_special_characters_required", True):
                    issues.append("Special chars not required")
            else:
                issues.append("No password policy configured")

            report.results.append(CISCheckResult(
                check_id="CIS-1.7",
                title="Ensure IAM password policy is strong",
                category="Identity & Access Management",
                severity="high",
                status="FAIL" if issues else "PASS",
                affected_resources=issues,
                evidence=(
                    "; ".join(issues) if issues
                    else "Password policy meets CIS requirements"
                ),
                remediation="Identity > Authentication Settings > Password Policy",
                cis_section="1.7",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-1.7",
                title="Ensure IAM password policy is strong",
                category="Identity & Access Management",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="1.7",
            ))

    # ==================================================================
    # SECTION 2: Networking
    # ==================================================================
    def _check_networking(self, network, compartments, report):
        """Run all networking CIS checks."""

        ssh_open = []       # CIS-2.1
        rdp_open = []       # CIS-2.2
        all_open = []       # CIS-2.3 — any port from 0.0.0.0/0
        public_subnets = [] # CIS-2.4

        for comp in compartments:
            cid = comp["id"]
            cname = comp["name"]

            # Security Lists
            try:
                seclists = network.list_security_lists(cid).data
                for sl in seclists:
                    for rule in (sl.ingress_security_rules or []):
                        src = getattr(rule, "source", "")
                        if src != "0.0.0.0/0":
                            continue

                        # Check TCP port ranges
                        tcp = getattr(rule, "tcp_options", None)
                        if tcp:
                            dst_range = getattr(tcp, "destination_port_range", None)
                            if dst_range:
                                lo = getattr(dst_range, "min", 0)
                                hi = getattr(dst_range, "max", 0)
                                if lo <= 22 <= hi:
                                    ssh_open.append(
                                        f"{sl.display_name} ({cname})"
                                    )
                                if lo <= 3389 <= hi:
                                    rdp_open.append(
                                        f"{sl.display_name} ({cname})"
                                    )
                            else:
                                # All ports open
                                all_open.append(
                                    f"{sl.display_name} ({cname}) — all TCP"
                                )
                        elif not tcp:
                            # No TCP options = all protocols
                            proto = getattr(rule, "protocol", "all")
                            if proto == "all":
                                all_open.append(
                                    f"{sl.display_name} ({cname}) — all protocols"
                                )
            except Exception:
                pass

            # Subnets
            try:
                subnets = network.list_subnets(cid).data
                for sub in subnets:
                    if not getattr(sub, "prohibit_public_ip_on_vnic", False):
                        public_subnets.append(
                            f"{sub.display_name} ({cname})"
                        )
            except Exception:
                pass

        # CIS-2.1: SSH from 0.0.0.0/0
        report.results.append(CISCheckResult(
            check_id="CIS-2.1",
            title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
            category="Networking",
            severity="critical",
            status="FAIL" if ssh_open else "PASS",
            affected_resources=list(set(ssh_open))[:20],
            evidence=(
                f"{len(ssh_open)} security list(s) allow SSH from anywhere"
                if ssh_open else "No unrestricted SSH access found"
            ),
            remediation="Restrict SSH (port 22) to specific CIDR ranges",
            cis_section="2.1",
        ))

        # CIS-2.2: RDP from 0.0.0.0/0
        report.results.append(CISCheckResult(
            check_id="CIS-2.2",
            title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
            category="Networking",
            severity="critical",
            status="FAIL" if rdp_open else "PASS",
            affected_resources=list(set(rdp_open))[:20],
            evidence=(
                f"{len(rdp_open)} security list(s) allow RDP from anywhere"
                if rdp_open else "No unrestricted RDP access found"
            ),
            remediation="Restrict RDP (port 3389) to specific CIDR ranges",
            cis_section="2.2",
        ))

        # CIS-2.3: Overly permissive ingress (all ports from 0.0.0.0/0)
        report.results.append(CISCheckResult(
            check_id="CIS-2.3",
            title="Ensure no security lists allow unrestricted ingress (all ports from 0.0.0.0/0)",
            category="Networking",
            severity="critical",
            status="FAIL" if all_open else "PASS",
            affected_resources=list(set(all_open))[:20],
            evidence=(
                f"{len(all_open)} overly permissive rule(s)"
                if all_open else "No unrestricted ingress rules found"
            ),
            remediation="Remove or restrict rules allowing all traffic from 0.0.0.0/0",
            cis_section="2.3",
        ))

        # CIS-2.4: Public subnets
        report.results.append(CISCheckResult(
            check_id="CIS-2.4",
            title="Ensure subnets prohibit public IP assignment where not required",
            category="Networking",
            severity="medium",
            status="FAIL" if public_subnets else "PASS",
            affected_resources=public_subnets[:20],
            evidence=(
                f"{len(public_subnets)} subnet(s) allow public IPs"
                if public_subnets
                else "All subnets prohibit public IP assignment"
            ),
            remediation="Set 'Prohibit Public IP on VNIC' for private subnets",
            cis_section="2.4",
        ))

    # ==================================================================
    # SECTION 3: Storage
    # ==================================================================
    def _check_storage(self, objstore, compartments, report):
        """Run storage CIS checks (Object Storage buckets)."""

        public_buckets = []     # CIS-3.1
        no_versioning = []      # CIS-3.2
        no_cmk = []             # CIS-3.3

        try:
            namespace = objstore.get_namespace().data
        except Exception as e:
            logger.warning("Could not get namespace: %s", e)
            return

        for comp in compartments:
            cid = comp["id"]
            cname = comp["name"]
            try:
                buckets = objstore.list_buckets(namespace, cid).data
                for b_summary in buckets:
                    try:
                        bucket = objstore.get_bucket(
                            namespace, b_summary.name
                        ).data

                        # CIS-3.1: Public access
                        access = getattr(bucket, "public_access_type", "NoPublicAccess")
                        if access and access != "NoPublicAccess":
                            public_buckets.append(
                                f"{bucket.name} ({cname}) — {access}"
                            )

                        # CIS-3.2: Versioning
                        ver = getattr(bucket, "versioning", None)
                        if ver != "Enabled":
                            no_versioning.append(f"{bucket.name} ({cname})")

                        # CIS-3.3: CMK encryption
                        kms = getattr(bucket, "kms_key_id", None)
                        if not kms:
                            no_cmk.append(f"{bucket.name} ({cname})")

                    except Exception:
                        pass
            except Exception:
                pass

        report.results.append(CISCheckResult(
            check_id="CIS-3.1",
            title="Ensure Object Storage buckets are not publicly accessible",
            category="Storage",
            severity="critical",
            status="FAIL" if public_buckets else "PASS",
            affected_resources=public_buckets[:20],
            evidence=(
                f"{len(public_buckets)} public bucket(s)"
                if public_buckets
                else "No publicly accessible buckets found"
            ),
            remediation="Set bucket access type to 'NoPublicAccess'",
            cis_section="3.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-3.2",
            title="Ensure Object Storage buckets have versioning enabled",
            category="Storage",
            severity="medium",
            status="FAIL" if no_versioning else "PASS",
            affected_resources=no_versioning[:20],
            evidence=(
                f"{len(no_versioning)} bucket(s) without versioning"
                if no_versioning
                else "All buckets have versioning enabled"
            ),
            remediation="Enable versioning on Object Storage buckets",
            cis_section="3.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-3.3",
            title="Ensure Object Storage buckets are encrypted with customer-managed keys",
            category="Storage",
            severity="high",
            status="FAIL" if no_cmk else "PASS",
            affected_resources=no_cmk[:20],
            evidence=(
                f"{len(no_cmk)} bucket(s) using Oracle-managed encryption"
                if no_cmk
                else "All buckets encrypted with customer-managed keys"
            ),
            remediation="Configure customer-managed encryption keys (Vault > Keys)",
            cis_section="3.3",
        ))

    # ==================================================================
    # SECTION 4: Compute
    # ==================================================================
    def _check_compute(self, compute, network, compartments, report):
        """Run compute-related CIS checks."""

        legacy_metadata = []   # CIS-4.1
        no_monitoring = []     # CIS-4.2
        public_instances = []  # CIS-4.3

        for comp in compartments:
            cid = comp["id"]
            cname = comp["name"]
            try:
                instances = compute.list_instances(
                    cid, lifecycle_state="RUNNING"
                ).data

                for inst in instances:
                    name = inst.display_name

                    # CIS-4.1: Legacy metadata service
                    inst_opts = getattr(inst, "instance_options", None)
                    if inst_opts:
                        legacy = getattr(
                            inst_opts,
                            "are_legacy_imds_endpoints_disabled",
                            None,
                        )
                        if legacy is False:
                            legacy_metadata.append(f"{name} ({cname})")

                    # CIS-4.2: Monitoring agent
                    agent_cfg = getattr(inst, "agent_config", None)
                    if agent_cfg:
                        monitoring = getattr(
                            agent_cfg, "is_monitoring_disabled", None
                        )
                        if monitoring is True:
                            no_monitoring.append(f"{name} ({cname})")

                    # CIS-4.3: Public IP check via VNIC attachments
                    try:
                        vnics = compute.list_vnic_attachments(
                            cid, instance_id=inst.id
                        ).data
                        for va in vnics:
                            try:
                                vnic = network.get_vnic(va.vnic_id).data
                                if getattr(vnic, "public_ip", None):
                                    public_instances.append(
                                        f"{name} ({cname}) — {vnic.public_ip}"
                                    )
                            except Exception:
                                pass
                    except Exception:
                        pass

            except Exception:
                pass

        report.results.append(CISCheckResult(
            check_id="CIS-4.1",
            title="Ensure Compute Instance Legacy Metadata service endpoint is disabled",
            category="Compute",
            severity="high",
            status="FAIL" if legacy_metadata else "PASS",
            affected_resources=legacy_metadata[:20],
            evidence=(
                f"{len(legacy_metadata)} instance(s) with legacy IMDS enabled"
                if legacy_metadata
                else "All instances have legacy IMDS disabled"
            ),
            remediation="Disable legacy metadata service on instances",
            cis_section="4.1",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.2",
            title="Ensure monitoring agent is enabled on all instances",
            category="Compute",
            severity="medium",
            status="FAIL" if no_monitoring else "PASS",
            affected_resources=no_monitoring[:20],
            evidence=(
                f"{len(no_monitoring)} instance(s) with monitoring disabled"
                if no_monitoring
                else "All instances have monitoring enabled"
            ),
            remediation="Enable Oracle Cloud Agent monitoring plugin",
            cis_section="4.2",
        ))

        report.results.append(CISCheckResult(
            check_id="CIS-4.3",
            title="Ensure compute instances do not have public IP addresses unless required",
            category="Compute",
            severity="medium",
            status="FAIL" if public_instances else "PASS",
            affected_resources=list(set(public_instances))[:20],
            evidence=(
                f"{len(public_instances)} instance(s) with public IPs"
                if public_instances
                else "No instances with public IPs found"
            ),
            remediation="Remove public IPs or ensure they are required for the workload",
            cis_section="4.3",
        ))

    # ==================================================================
    # SECTION 5: Logging & Monitoring
    # ==================================================================
    def _check_logging(self, tenancy_id, report):
        """Run logging/monitoring CIS checks."""

        # CIS-5.1: Audit log retention
        try:
            import oci
            audit_client = oci.audit.AuditClient(self.collector.config)
            cfg = audit_client.get_configuration(tenancy_id).data
            retention = getattr(cfg, "retention_period_days", 0)

            report.results.append(CISCheckResult(
                check_id="CIS-5.1",
                title="Ensure audit log retention is set to 365 days",
                category="Logging & Monitoring",
                severity="high",
                status="PASS" if retention >= 365 else "FAIL",
                evidence=f"Current retention: {retention} days",
                remediation="Set audit retention to 365 days: Governance > Audit > Configuration",
                cis_section="5.1",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-5.1",
                title="Ensure audit log retention is set to 365 days",
                category="Logging & Monitoring",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="5.1",
            ))

        # CIS-5.2: Cloud Guard enabled
        try:
            import oci
            cg_client = oci.cloud_guard.CloudGuardClient(self.collector.config)
            cg_cfg = cg_client.get_configuration(tenancy_id).data
            cg_status = getattr(cg_cfg, "status", "DISABLED")

            report.results.append(CISCheckResult(
                check_id="CIS-5.2",
                title="Ensure Cloud Guard is enabled in the root compartment",
                category="Logging & Monitoring",
                severity="high",
                status="PASS" if cg_status == "ENABLED" else "FAIL",
                evidence=f"Cloud Guard status: {cg_status}",
                remediation="Enable Cloud Guard: Security > Cloud Guard > Enable",
                cis_section="5.2",
            ))
        except Exception as e:
            report.results.append(CISCheckResult(
                check_id="CIS-5.2",
                title="Ensure Cloud Guard is enabled in the root compartment",
                category="Logging & Monitoring",
                severity="high",
                status="ERROR", evidence=str(e), cis_section="5.2",
            ))

    # ==================================================================
    # MOCK mode (offline / demo)
    # ==================================================================
    def _run_mock(self, report: CISBenchmarkReport):
        """Generate realistic mock results for demo/testing."""
        report.scan_mode = "mock"
        report.region = "us-ashburn-1"
        report.tenancy_name = "mock-tenancy"

        mock_checks = [
            # IAM
            ("CIS-1.1", "Ensure MFA is enabled for all users", "Identity & Access Management",
             "critical", "FAIL", "3 user(s) without MFA",
             ["user_admin", "user_dev1", "user_ops"], "Enable MFA for all users"),
            ("CIS-1.2", "Ensure API keys are rotated within 90 days", "Identity & Access Management",
             "high", "FAIL", "2 stale API key(s) older than 90 days",
             ["admin_user (key: a1b2c3…)", "svc_account (key: d4e5f6…)"], "Rotate API keys"),
            ("CIS-1.3", "Ensure no API keys for tenancy admins", "Identity & Access Management",
             "critical", "FAIL", "1 admin(s) with API keys",
             ["tenancy_admin"], "Remove API keys from admin accounts"),
            ("CIS-1.4", "Ensure auth tokens are rotated within 90 days", "Identity & Access Management",
             "high", "PASS", "All auth tokens rotated within 90 days", [], ""),
            ("CIS-1.5", "Ensure IAM policies do not grant overly broad permissions", "Identity & Access Management",
             "high", "FAIL", "2 overly permissive statement(s)",
             ["DevPolicy: allow group Devs to manage all-resources…",
              "TestPolicy: allow group QA to use all-resources…"],
             "Restrict to least-privilege"),
            ("CIS-1.6", "Ensure users inactive for 90+ days are disabled", "Identity & Access Management",
             "medium", "FAIL", "4 inactive user(s)",
             ["old_user1 (never logged in)", "old_user2", "contractor1", "temp_admin"],
             "Disable or remove inactive users"),
            ("CIS-1.7", "Ensure IAM password policy is strong", "Identity & Access Management",
             "high", "FAIL", "Min length 8 (should be ≥14)",
             ["Min length 8 (should be ≥14)"], "Strengthen password policy"),

            # Networking
            ("CIS-2.1", "Ensure no security lists allow SSH from 0.0.0.0/0", "Networking",
             "critical", "FAIL", "3 security list(s) allow SSH from anywhere",
             ["Default-SL (DevTest)", "WebApp-SL (Prod)", "Test-SL (Sandbox)"],
             "Restrict SSH to specific CIDR ranges"),
            ("CIS-2.2", "Ensure no security lists allow RDP from 0.0.0.0/0", "Networking",
             "critical", "PASS", "No unrestricted RDP access found", [], ""),
            ("CIS-2.3", "Ensure no security lists allow unrestricted ingress", "Networking",
             "critical", "FAIL", "1 overly permissive rule(s)",
             ["Legacy-SL (OldComp) — all protocols"],
             "Remove rules allowing all traffic from 0.0.0.0/0"),
            ("CIS-2.4", "Ensure subnets prohibit public IP assignment where not required", "Networking",
             "medium", "FAIL", "12 subnet(s) allow public IPs",
             ["pub-sub-1 (DevTest)", "pub-sub-2 (Prod)", "app-sub (Staging)"],
             "Set 'Prohibit Public IP on VNIC' for private subnets"),

            # Storage
            ("CIS-3.1", "Ensure Object Storage buckets are not publicly accessible", "Storage",
             "critical", "FAIL", "2 public bucket(s)",
             ["static-assets (Prod) — ObjectRead", "data-export (DevTest) — ObjectReadWrite"],
             "Set bucket access to 'NoPublicAccess'"),
            ("CIS-3.2", "Ensure Object Storage buckets have versioning enabled", "Storage",
             "medium", "FAIL", "8 bucket(s) without versioning",
             ["logs-bucket (Prod)", "backup-bucket (DR)", "temp-data (DevTest)"],
             "Enable versioning on buckets"),
            ("CIS-3.3", "Ensure Object Storage buckets use customer-managed encryption", "Storage",
             "high", "FAIL", "15 bucket(s) using Oracle-managed encryption",
             ["app-data (Prod)", "db-backups (Prod)", "config-store (DevTest)"],
             "Configure CMK encryption via Vault"),

            # Compute
            ("CIS-4.1", "Ensure legacy metadata service endpoint is disabled", "Compute",
             "high", "FAIL", "5 instance(s) with legacy IMDS enabled",
             ["web-server-1 (Prod)", "app-server-2 (Prod)", "dev-box (DevTest)"],
             "Disable legacy metadata service on instances"),
            ("CIS-4.2", "Ensure monitoring agent is enabled on all instances", "Compute",
             "medium", "FAIL", "3 instance(s) with monitoring disabled",
             ["batch-job-1 (Prod)", "test-vm (DevTest)", "jump-host (Staging)"],
             "Enable Oracle Cloud Agent monitoring plugin"),
            ("CIS-4.3", "Ensure instances do not have public IPs unless required", "Compute",
             "medium", "FAIL", "7 instance(s) with public IPs",
             ["web-1 (Prod) — 129.213.x.x", "bastion (DevTest) — 144.24.x.x"],
             "Remove public IPs or ensure they are required"),

            # Logging
            ("CIS-5.1", "Ensure audit log retention is set to 365 days", "Logging & Monitoring",
             "high", "FAIL", "Current retention: 90 days",
             [], "Set audit retention to 365 days"),
            ("CIS-5.2", "Ensure Cloud Guard is enabled in the root compartment", "Logging & Monitoring",
             "high", "PASS", "Cloud Guard status: ENABLED", [], ""),
        ]

        for (cid, title, cat, sev, status, evidence,
             resources, remediation) in mock_checks:
            report.results.append(CISCheckResult(
                check_id=cid,
                title=title,
                category=cat,
                severity=sev,
                status=status,
                affected_resources=resources,
                evidence=evidence,
                remediation=remediation,
                cis_section=cid.replace("CIS-", ""),
            ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_cis_benchmark(
    collector=None,
    progress_callback=None,
) -> Dict[str, Any]:
    """Run CIS OCI benchmark and return results as a dict."""
    runner = CISBenchmarkRunner(
        collector=collector,
        progress_callback=progress_callback,
    )
    report = runner.run()
    return report.to_dict()
