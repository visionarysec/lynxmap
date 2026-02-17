"""
LynxMap - OCI Collector
Fetches infrastructure data from Oracle Cloud Infrastructure
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OCICollector:
    """Collector for OCI infrastructure data"""
    
    config: Optional[Dict[str, Any]]
    clients: Dict[str, Any]
    compartments: List[Dict[str, Any]]
    
    def __init__(self, config_path: Optional[str] = None, profile: str = "DEFAULT"):
        self.config_path = config_path or os.path.expanduser("~/.oci/config")
        self.profile = profile
        self.config = None
        self.clients = {}
        self.compartments = []  # Cache for compartments
        self._initialize()
    
    def _initialize(self):
        """Initialize OCI clients"""
        try:
            import oci
            self.config = oci.config.from_file(self.config_path, self.profile)
            self._setup_clients()
            logger.info(f"OCI Collector initialized with profile: {self.profile}")
        except ImportError:
            logger.warning("OCI SDK not installed. Using mock data.")
            self.config = None
        except Exception as e:
            logger.warning(f"Could not load OCI config: {e}. Using mock data.")
            self.config = None
    
    def _setup_clients(self):
        """Setup OCI service clients"""
        if not self.config:
            return
            
        import oci
        try:
            self.clients = {
                "identity": oci.identity.IdentityClient(self.config),
                "compute": oci.core.ComputeClient(self.config),
                "network": oci.core.VirtualNetworkClient(self.config),
                "object_storage": oci.object_storage.ObjectStorageClient(self.config),
                "database": oci.database.DatabaseClient(self.config),
                "load_balancer": oci.load_balancer.LoadBalancerClient(self.config),
            }
        except Exception as e:
            logger.error(f"Error setting up OCI clients: {e}")
            self.config = None
    
    def collect_all(self):
        """
        Collect all resources from OCI and normalize to standard asset format.
        Yields batches of assets as they are collected.
        """
        config = self.config
        if not config:
            logger.info("Using mock data for collection")
            yield self._get_mock_data_assets()
            return

        logger.info("Starting full OCI collection...")
        
        # 1. Collect Compartments (Foundation)
        self.compartments = self._collect_compartment_details()
        logger.info(f"Found {len(self.compartments)} compartments")
        
        # 2. Iterate through compartments for regional resources
        # We'll use the tenancy ID as the root for global resources
        tenancy_id = config.get("tenancy")
        if not tenancy_id: # Safety check
             logger.error("No tenancy ID found in config")
             return

        # Global Resources
        global_assets = []
        global_assets.extend(self._collect_users())
        global_assets.extend(self._collect_groups())
        global_assets.extend(self._collect_policies())
        if global_assets:
            yield global_assets
        
        # Regional Resources (per compartment)
        for i, comp in enumerate(self.compartments):
            comp_id = comp['id']
            comp_name = comp['name']
            
            # Skip if compartment is not active
            if comp.get('lifecycle_state') != 'ACTIVE':
                continue
                
            try:
                compartment_assets = []
                # Compute
                compartment_assets.extend(self._collect_instances(comp_id, comp_name))
                
                # Network
                compartment_assets.extend(self._collect_vcns(comp_id, comp_name))
                compartment_assets.extend(self._collect_subnets(comp_id, comp_name))
                compartment_assets.extend(self._collect_network_security_groups(comp_id, comp_name))
                compartment_assets.extend(self._collect_security_lists(comp_id, comp_name))
                
                # Storage
                compartment_assets.extend(self._collect_buckets(comp_id, comp_name))
                
                # Load Balancers
                compartment_assets.extend(self._collect_load_balancers(comp_id, comp_name))
                
                if compartment_assets:
                    yield compartment_assets
                    
                # Log progress periodically
                if (i + 1) % 5 == 0:
                    logger.info(f"Processed {i + 1}/{len(self.compartments)} compartments")
                
            except Exception as e:
                logger.error(f"Error collecting resources in compartment {comp_name}: {e}")


    def _collect_compartment_details(self) -> List[Dict]:
        """Collect raw compartment hierarchy"""
        config = self.config
        if not config:
            return []
        
        # Check for identity client
        if "identity" not in self.clients:
            logger.error("Identity client not initialized")
            return []

        client = self.clients["identity"]
        tenancy_id = config.get("tenancy")
        if not tenancy_id:
             logger.error("Tenancy ID missing from config")
             return []
        
        compartments = []
        try:
            # Add root compartment
            root_comp = client.get_compartment(tenancy_id).data
            compartments.append({
                "id": root_comp.id,
                "name": root_comp.name,
                "description": root_comp.description,
                "lifecycle_state": root_comp.lifecycle_state,
                "parent_compartment_id": None
            })
            
            # Add sub compartments
            response = client.list_compartments(tenancy_id, compartment_id_in_subtree=True, access_level="ACCESSIBLE")
            for comp in response.data:
                compartments.append({
                    "id": comp.id,
                    "name": comp.name,
                    "description": comp.description,
                    "lifecycle_state": comp.lifecycle_state,
                    "parent_compartment_id": comp.compartment_id
                })
        except Exception as e:
            logger.error(f"Error collecting compartments: {e}")
            
        return compartments

    def _collect_users(self) -> List[Dict]:
        """Collect IAM users"""
        users = []
        try:
            client = self.clients["identity"]
            tenancy_id = self.config["tenancy"]
            response = client.list_users(tenancy_id)
            
            for user in response.data:
                users.append({
                    "asset_id": user.id,
                    "asset_type": "user",
                    "name": user.name,
                    "compartment": "tenancy",
                    "region": self.config.get("region", "global"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "email": user.email,
                        "lifecycle_state": user.lifecycle_state,
                        "is_mfa_activated": getattr(user, "is_mfa_activated", False),
                        "time_created": str(user.time_created)
                    }
                })
        except Exception as e:
            logger.error(f"Error collecting users: {e}")
        return users

    def _collect_groups(self) -> List[Dict]:
        groups = []
        try:
            client = self.clients["identity"]
            tenancy_id = self.config["tenancy"]
            response = client.list_groups(tenancy_id)
            for group in response.data:
                groups.append({
                    "asset_id": group.id,
                    "asset_type": "group",
                    "name": group.name,
                    "compartment": "tenancy",
                    "region": self.config.get("region", "global"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "description": group.description,
                        "time_created": str(group.time_created)
                    }
                })
        except Exception as e:
            logger.error(f"Error collecting groups: {e}")
        return groups

    def _collect_policies(self) -> List[Dict]:
        policies = []
        try:
            client = self.clients["identity"]
            tenancy_id = self.config["tenancy"]
            response = client.list_policies(tenancy_id)
            for policy in response.data:
                policies.append({
                    "asset_id": policy.id,
                    "asset_type": "policy",
                    "name": policy.name,
                    "compartment": "tenancy",
                    "region": self.config.get("region", "global"),
                    "scan_status": "scanned", # Policies are text, easy to scan
                    "metadata": {
                        "statements": policy.statements,
                        "description": policy.description,
                        "version_date": str(policy.version_date) if policy.version_date else None
                    }
                })
        except Exception as e:
            logger.error(f"Error collecting policies: {e}")
        return policies

    def _collect_instances(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        instances = []
        try:
            client = self.clients["compute"]
            response = client.list_instances(compartment_id)
            for inst in response.data:
                # Get primary vnic for IP address (simplified)
                instances.append({
                    "asset_id": inst.id,
                    "asset_type": "vm",
                    "name": inst.display_name,
                    "compartment": compartment_name,
                    "region": inst.region,
                    "scan_status": "not_scanned",
                    "metadata": {
                        "shape": inst.shape,
                        "lifecycle_state": inst.lifecycle_state,
                        "availability_domain": inst.availability_domain,
                        "time_created": str(inst.time_created)
                    }
                })
        except Exception as e:
            # Specific compartments might fail, log debug
            logger.debug(f"Error collecting instances in {compartment_name}: {e}")
        return instances

    def _collect_vcns(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            response = client.list_vcns(compartment_id)
            for vcn in response.data:
                assets.append({
                    "asset_id": vcn.id,
                    "asset_type": "vcn",
                    "name": vcn.display_name,
                    "compartment": compartment_name,
                    "region": self.config.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "cidr_block": vcn.cidr_block,
                        "dns_label": vcn.dns_label,
                        "lifecycle_state": vcn.lifecycle_state
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_subnets(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            response = client.list_subnets(compartment_id)
            for subnet in response.data:
                assets.append({
                    "asset_id": subnet.id,
                    "asset_type": "subnet",
                    "name": subnet.display_name,
                    "compartment": compartment_name,
                    "region": self.config.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "cidr_block": subnet.cidr_block,
                        "vcn_id": subnet.vcn_id,
                        "prohibit_public_ip_on_vnic": subnet.prohibit_public_ip_on_vnic,
                        "lifecycle_state": subnet.lifecycle_state
                    }
                })
        except Exception:
            pass
        return assets
    
    def _collect_network_security_groups(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            response = client.list_network_security_groups(compartment_id)
            for nsg in response.data:
                assets.append({
                    "asset_id": nsg.id,
                    "asset_type": "nsg",
                    "name": nsg.display_name,
                    "compartment": compartment_name,
                    "region": self.config.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "vcn_id": nsg.vcn_id,
                        "lifecycle_state": nsg.lifecycle_state
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_security_lists(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        assets = []
        try:
            client = self.clients["network"]
            response = client.list_security_lists(compartment_id)
            for sl in response.data:
                assets.append({
                    "asset_id": sl.id,
                    "asset_type": "security_list",
                    "name": sl.display_name,
                    "compartment": compartment_name,
                    "region": self.config.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "vcn_id": sl.vcn_id,
                        "lifecycle_state": sl.lifecycle_state,
                        "ingress_description": f"{len(sl.ingress_security_rules)} rules",
                        "egress_description": f"{len(sl.egress_security_rules)} rules"
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_buckets(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        assets = []
        try:
            client = self.clients["object_storage"]
            namespace = client.get_namespace().data
            response = client.list_buckets(namespace, compartment_id)
            for bucket in response.data:
                assets.append({
                    "asset_id": bucket.name, # Buckets don't always have OCIDs in list response, name is unique in namespace
                    "asset_type": "bucket",
                    "name": bucket.name,
                    "compartment": compartment_name,
                    "region": self.config.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "namespace": namespace,
                        "time_created": str(bucket.time_created),
                        "public_access_type": "unknown" # Need get_bucket to verify public access
                    }
                })
        except Exception:
            pass
        return assets

    def _collect_load_balancers(self, compartment_id: str, compartment_name: str) -> List[Dict]:
        assets = []
        try:
            client = self.clients["load_balancer"]
            response = client.list_load_balancers(compartment_id)
            for lb in response.data:
                assets.append({
                    "asset_id": lb.id,
                    "asset_type": "lb",
                    "name": lb.display_name,
                    "compartment": compartment_name,
                    "region": self.config.get("region", "unknown"),
                    "scan_status": "not_scanned",
                    "metadata": {
                        "shape_name": lb.shape_name,
                        "is_private": lb.is_private,
                        "lifecycle_state": lb.lifecycle_state,
                        "ip_addresses": [ip.ip_address for ip in lb.ip_addresses]
                    }
                })
        except Exception:
            pass
        return assets

    def _get_mock_data_assets(self) -> List[Dict]:
        """Return mock data compatible with the database schema"""
        # Create some realistic mock data for visualization
        assets = []
        
        # 1. Compartment Structure
        # Root -> Prod -> Net, App
        # Root -> Dev
        
        # 2. Add some VMs
        assets.append({
            "asset_id": "ocid1.instance.oc1.phx.mock1",
            "asset_type": "vm",
            "name": "prod-web-server-01",
            "compartment": "FSC_HCP_systems_DevTest",
            "region": "us-phoenix-1",
            "scan_status": "scanned",
            "risk_score": 10,
            "metadata": {"shape": "VM.Standard2.1", "public_ip": "140.2.1.1"}
        })
        assets.append({
            "asset_id": "ocid1.instance.oc1.phx.mock2",
            "asset_type": "vm",
            "name": "prod-db-server-01",
            "compartment": "FSC_HCP_systems_DevTest",
            "region": "us-phoenix-1",
            "scan_status": "scanned",
            "risk_score": 5,
            "metadata": {"shape": "VM.Standard2.4", "public_ip": None}
        })
        
        # 3. Add Buckets
        assets.append({
            "asset_id": "mock-bucket-public",
            "asset_type": "bucket",
            "name": "public-assets-bucket",
            "compartment": "FSC_HCP_systems_DevTest",
            "region": "us-phoenix-1",
            "scan_status": "scanned",
            "risk_score": 80,
            "metadata": {"public_access": "ObjectRead", "namespace": "test-ns"}
        })
        
        # 4. IAM Policies
        assets.append({
            "asset_id": "ocid1.policy.oc1..mock1",
            "asset_type": "policy",
            "name": "Manage-All-Policy",
            "compartment": "root",
            "region": "global",
            "scan_status": "scanned",
            "risk_score": 90,
            "metadata": {"statements": ["Allow group Administrators to manage all-resources in tenancy"]}
        })
        
        # Fill in more mock data to match the UI screenshots
        for i in range(5):
             assets.append({
                "asset_id": f"ocid1.vnic.oc1.phx.mock{i}",
                "asset_type": "vnic",
                "name": f"primary-vnic-{i}",
                "compartment": "FSC_HCP_systems_DevTest",
                "region": "us-phoenix-1",
                "scan_status": "scanned",
                "metadata": {"public_ip": f"129.1.{i}.1"}
            })
            
        return assets
