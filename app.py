#!/usr/bin/env python3
"""
Simple Zabbix to NetBox Synchronizer for DC-Karaganda
Focus on VMware hypervisors synchronization
"""

import os
import re
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pyzabbix import ZabbixAPI
import pynetbox
import urllib3
from dotenv import load_dotenv

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class KaragandaDCSync:
    """Synchronizer for Karaganda DC servers"""
    
    def __init__(self, zabbix_url: str, zabbix_user: str, zabbix_pass: str,
                 netbox_url: str, netbox_token: str):
        """Initialize with credentials"""
        self.zabbix_url = zabbix_url
        self.zabbix_user = zabbix_user  
        self.zabbix_pass = zabbix_pass
        self.netbox_url = netbox_url
        self.netbox_token = netbox_token
        
        self.zabbix = None
        self.netbox = None
        
        # Statistics
        self.stats = {
            'total': 0,
            'created': 0,
            'updated': 0,
            'failed': 0,
            'skipped': 0
        }
    
    def connect(self) -> bool:
        """Connect to Zabbix and NetBox"""
        try:
            # Connect to Zabbix
            logger.info(f"Connecting to Zabbix at {self.zabbix_url}")
            self.zabbix = ZabbixAPI(self.zabbix_url)
            self.zabbix.session.verify = False
            self.zabbix.login(self.zabbix_user, self.zabbix_pass)
            logger.info("✓ Connected to Zabbix")
            
            # Connect to NetBox
            logger.info(f"Connecting to NetBox at {self.netbox_url}")
            self.netbox = pynetbox.api(self.netbox_url, token=self.netbox_token)
            self.netbox.http_session.verify = False
            
            # Test connection
            self.netbox.status()
            logger.info("✓ Connected to NetBox")
            
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def get_karaganda_hypervisors(self) -> List[Dict]:
        """Get VMware hypervisors from DC-Karaganda group"""
        logger.info("Fetching VMware hypervisors from DC-Karaganda...")
        
        try:
            # First, find the VMware hypervisor discovery group for Karaganda
            groups = self.zabbix.hostgroup.get(
                filter={'name': ['VMware hypervisor discovery: DC-Karaganda']},
                output=['groupid', 'name']
            )
            
            if not groups:
                logger.warning("VMware hypervisor discovery: DC-Karaganda group not found")
                logger.info("Looking for alternative groups...")
                
                # Try to find hosts by pattern
                all_hosts = self.zabbix.host.get(
                    output='extend',
                    selectInventory='extend',
                    selectInterfaces='extend',
                    selectGroups='extend',
                    selectParentTemplates=['templateid', 'name'],
                    selectTags='extend'
                )
                
                karaganda_hypervisors = []
                for host in all_hosts:
                    hostname = host.get('host', '').lower()
                    
                    # Check if it's a Karaganda server
                    # Pattern: dc01-krg-comp-*, dc01-krg-edge-*, etc.
                    if 'dc01-krg' in hostname or 'krg-comp' in hostname or 'krg-edge' in hostname:
                        # Check if it's a server (not network equipment)
                        if self._is_vmware_server(host):
                            karaganda_hypervisors.append(host)
                            logger.debug(f"Found Karaganda server: {host.get('host')}")
                
            else:
                # Get hosts from the VMware group
                group_id = groups[0]['groupid']
                logger.info(f"Found group: {groups[0]['name']} (ID: {group_id})")
                
                karaganda_hypervisors = self.zabbix.host.get(
                    groupids=[group_id],
                    output='extend',
                    selectInventory='extend',
                    selectInterfaces='extend',
                    selectGroups='extend',
                    selectParentTemplates=['templateid', 'name'],
                    selectTags='extend'
                )
            
            logger.info(f"Found {len(karaganda_hypervisors)} VMware hypervisors in DC-Karaganda")
            
            # Debug: show first few hostnames
            if karaganda_hypervisors:
                logger.debug("Sample hosts found:")
                for host in karaganda_hypervisors[:5]:
                    logger.debug(f"  - {host.get('host')}")
            
            return karaganda_hypervisors
            
        except Exception as e:
            logger.error(f"Error fetching hosts: {e}")
            return []
    
    def _is_vmware_server(self, host: Dict) -> bool:
        """Check if host is a VMware server (not network equipment)"""
        hostname = host.get('host', '').lower()
        
        # Exclude network equipment patterns
        network_patterns = ['sw01', 'sw02', 'rt01', 'rt02', 'fw01', 'fw02', '-switch', '-router', '-firewall']
        if any(pattern in hostname for pattern in network_patterns):
            return False
        
        # Check for server patterns
        server_patterns = ['srv', 'server', 'esxi', 'esx', 'vmware']
        if any(pattern in hostname for pattern in server_patterns):
            return True
        
        # Check templates for VMware/ESXi
        for template in host.get('parentTemplates', []):
            template_name = template.get('name', '').lower()
            if any(p in template_name for p in ['vmware', 'esxi', 'hypervisor']):
                return True
        
        # Check inventory OS for VMware/ESXi
        inventory = host.get('inventory', {})
        if isinstance(inventory, dict):
            os_name = inventory.get('os', '').lower()
            software = inventory.get('software', '').lower()
            
            if 'vmware' in os_name or 'esxi' in os_name:
                return True
            if 'vmware' in software or 'esxi' in software:
                return True
        
        # Check if hostname matches server naming pattern
        # Pattern: dc01-krg-comp-amd-srv01
        if re.match(r'dc\d+-krg-(comp|edge|mgmt|hm|gen|backup)-.*srv\d+', hostname):
            return True
        
        return False
    
    def _determine_device_role(self, hostname: str) -> str:
        """Determine device role based on hostname"""
        hostname_lower = hostname.lower()
        
        # Extract role from hostname pattern
        # Pattern: dc01-krg-[role]-amd-srv01
        match = re.search(r'dc\d+-krg-(comp|edge|mgmt|hm|gen|backup|vsbc)', hostname_lower)
        if match:
            role_type = match.group(1)
            if role_type in ['edge', 'vsbc']:
                return 'Edge-Cluster-Servers-All'
            elif role_type in ['comp', 'gen']:
                return 'Compute-Cluster-Servers-All'
            elif role_type in ['mgmt', 'hm', 'backup']:
                return 'MGMT-Cluster-Servers-All'
        
        # Fallback pattern matching
        if 'edge' in hostname_lower:
            return 'Edge-Cluster-Servers-All'
        elif 'comp' in hostname_lower or 'gen' in hostname_lower:
            return 'Compute-Cluster-Servers-All'
        elif 'mgmt' in hostname_lower or 'hm' in hostname_lower:
            return 'MGMT-Cluster-Servers-All'
        
        # Default for servers
        return 'Compute-Cluster-Servers-All'
    
    def _get_or_create_site(self, site_name: str):
        """Get or create site in NetBox"""
        # Check if site exists
        sites = list(self.netbox.dcim.sites.filter(name=site_name))
        if sites:
            return sites[0]
        
        # Create new site
        slug = re.sub(r'[^a-z0-9-]', '-', site_name.lower()).strip('-')
        logger.info(f"Creating new site: {site_name}")
        
        return self.netbox.dcim.sites.create(
            name=site_name,
            slug=slug,
            status='active',
            description='Karaganda Data Center',
            physical_address='132-й учетный квартал, Karaganda, Kazakhstan',
            comments='Created by Zabbix sync'
        )
    
    def _get_or_create_manufacturer(self, vendor: str):
        """Get or create manufacturer"""
        # Clean vendor name
        vendor_map = {
            'dell': 'Dell Technologies',
            'hp': 'Hewlett Packard Enterprise',
            'hpe': 'Hewlett Packard Enterprise', 
            'lenovo': 'Lenovo',
            'cisco': 'Cisco Systems',
            'intel': 'Intel Corporation',
            'supermicro': 'Super Micro Computer',
            'vmware': 'VMware'
        }
        
        vendor_clean = vendor
        if vendor:
            vendor_lower = vendor.lower().strip()
            for key, value in vendor_map.items():
                if key in vendor_lower:
                    vendor_clean = value
                    break
        
        if not vendor_clean or vendor_clean == '':
            vendor_clean = 'Unknown'
        
        # Check if exists
        manufacturers = list(self.netbox.dcim.manufacturers.filter(name=vendor_clean))
        if manufacturers:
            return manufacturers[0]
        
        # Create new
        slug = re.sub(r'[^a-z0-9-]', '-', vendor_clean.lower()).strip('-')
        logger.info(f"Creating new manufacturer: {vendor_clean}")
        
        return self.netbox.dcim.manufacturers.create(
            name=vendor_clean,
            slug=slug
        )
    
    def _get_or_create_device_type(self, model: str, manufacturer):
        """Get or create device type"""
        if not model or model == '':
            model = 'Generic Server'
        
        # Clean model name - remove manufacturer name if it's in the model
        model_clean = model
        if manufacturer.name in model:
            model_clean = model.replace(manufacturer.name, '').strip()
        
        # Check if exists
        device_types = list(self.netbox.dcim.device_types.filter(
            model=model_clean,
            manufacturer_id=manufacturer.id
        ))
        
        if device_types:
            return device_types[0]
        
        # Create new
        slug = re.sub(r'[^a-z0-9-]', '-', f"{manufacturer.name}-{model_clean}".lower()).strip('-')[:50]
        logger.info(f"Creating new device type: {model_clean}")
        
        return self.netbox.dcim.device_types.create(
            manufacturer=manufacturer.id,
            model=model_clean,
            slug=slug,
            u_height=2,  # Default 2U for servers
            is_full_depth=True
        )
    
    def _get_or_create_device_role(self, role_name: str):
        """Get or create device role"""
        # Check if exists
        roles = list(self.netbox.dcim.device_roles.filter(name=role_name))
        if roles:
            return roles[0]
        
        # This shouldn't happen as roles are pre-created, but just in case
        logger.warning(f"Role {role_name} not found, using default")
        
        # Use default role
        default_roles = list(self.netbox.dcim.device_roles.filter(name='Compute-Cluster-Servers-All'))
        if default_roles:
            return default_roles[0]
        
        # Create if nothing exists
        slug = re.sub(r'[^a-z0-9-]', '-', role_name.lower()).strip('-')
        return self.netbox.dcim.device_roles.create(
            name=role_name,
            slug=slug,
            color='0066cc'
        )
    
    def _get_primary_ip(self, interfaces: List[Dict]) -> Optional[str]:
        """Get primary IP from interfaces"""
        # Look for Agent interface
        for interface in interfaces:
            if interface.get('type') == '1':  # Agent
                ip = interface.get('ip', '')
                if ip and ip not in ['0.0.0.0', '127.0.0.1', '']:
                    return ip
        
        # Fallback to any valid IP
        for interface in interfaces:
            ip = interface.get('ip', '')
            if ip and ip not in ['0.0.0.0', '127.0.0.1', '']:
                return ip
        
        return None
    
    def sync_device(self, host: Dict) -> bool:
        """Sync single device to NetBox"""
        hostname = host.get('host', '')
        
        try:
            logger.info(f"Syncing device: {hostname}")
            
            # Get inventory data
            inventory = host.get('inventory', {})
            if isinstance(inventory, list):
                inventory = inventory[0] if inventory else {}
            elif not isinstance(inventory, dict):
                inventory = {}
            
            # Prepare device data
            site = self._get_or_create_site('DC Karaganda')
            role = self._get_or_create_device_role(self._determine_device_role(hostname))
            
            # Get or create manufacturer and device type
            vendor = inventory.get('vendor', 'Unknown')
            if not vendor or vendor == '':
                # Try to detect from hardware field
                hardware = inventory.get('hardware', '').lower()
                if 'dell' in hardware:
                    vendor = 'Dell'
                elif 'hp' in hardware or 'hpe' in hardware:
                    vendor = 'HPE'
                elif 'lenovo' in hardware:
                    vendor = 'Lenovo'
                else:
                    vendor = 'Unknown'
            
            manufacturer = self._get_or_create_manufacturer(vendor)
            
            model = inventory.get('model', '') or inventory.get('hardware', 'Generic Server')
            device_type = self._get_or_create_device_type(model, manufacturer)
            
            # Get primary IP
            primary_ip = self._get_primary_ip(host.get('interfaces', []))
            
            # Build comments
            comments_parts = []
            if inventory.get('alias'):
                comments_parts.append(f"Alias: {inventory['alias']}")
            if inventory.get('os'):
                comments_parts.append(f"OS: {inventory['os']}")
            if inventory.get('os_short'):
                comments_parts.append(f"OS Short: {inventory['os_short']}")
            if inventory.get('software_app_a'):
                comments_parts.append(f"Software: {inventory['software_app_a']}")
            
            # Add visible name if different from hostname
            visible_name = host.get('name', '')
            if visible_name and visible_name != hostname:
                comments_parts.append(f"Visible Name: {visible_name}")
            
            comments = '\n'.join(comments_parts)
            
            # Check if device exists
            existing_devices = list(self.netbox.dcim.devices.filter(name=hostname))
            
            if existing_devices:
                # Update existing device
                device = existing_devices[0]
                logger.info(f"Updating existing device: {hostname}")
                
                # Update fields
                device.device_type = device_type.id
                device.device_role = role.id
                device.site = site.id
                device.status = 'active' if host.get('status') == '0' else 'offline'
                device.comments = comments
                
                # Update serial if available
                serial = inventory.get('serialno_a', '')
                if serial:
                    device.serial = serial
                
                device.save()
                
                # Update custom fields
                if hasattr(device, 'custom_fields'):
                    device.custom_fields['zabbix_hostid'] = host.get('hostid')
                    device.custom_fields['last_sync'] = datetime.now().isoformat()
                    device.custom_fields['zabbix_visible_name'] = visible_name
                    device.save()
                
                self.stats['updated'] += 1
                logger.info(f"✓ Updated device: {hostname}")
                
            else:
                # Create new device
                logger.info(f"Creating new device: {hostname}")
                
                device_data = {
                    'name': hostname,
                    'device_type': device_type.id,
                    'device_role': role.id,
                    'site': site.id,
                    'status': 'active' if host.get('status') == '0' else 'offline',
                    'comments': comments
                }
                
                # Add serial if available
                serial = inventory.get('serialno_a', '')
                if serial:
                    device_data['serial'] = serial
                
                device = self.netbox.dcim.devices.create(**device_data)
                
                # Set custom fields
                if hasattr(device, 'custom_fields'):
                    device.custom_fields['zabbix_hostid'] = host.get('hostid')
                    device.custom_fields['last_sync'] = datetime.now().isoformat()
                    device.custom_fields['zabbix_visible_name'] = visible_name
                    device.save()
                
                self.stats['created'] += 1
                logger.info(f"✓ Created device: {hostname}")
            
            # Create or update primary IP if exists
            if primary_ip:
                self._sync_ip_address(device, primary_ip)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to sync device {hostname}: {e}")
            self.stats['failed'] += 1
            return False
    
    def _sync_ip_address(self, device, ip_address: str):
        """Sync IP address to NetBox"""
        try:
            # Check if IP exists
            ips = list(self.netbox.ipam.ip_addresses.filter(address=ip_address))
            
            if ips:
                ip = ips[0]
                logger.debug(f"IP {ip_address} already exists")
            else:
                # Create IP address
                ip = self.netbox.ipam.ip_addresses.create(
                    address=f"{ip_address}/32",
                    status='active',
                    description=f"Primary IP for {device.name}",
                    assigned_object_type='dcim.device',
                    assigned_object_id=device.id
                )
                logger.info(f"Created IP address: {ip_address}")
            
            # Set as primary IP for device
            device.primary_ip4 = ip.id
            device.save()
            
        except Exception as e:
            logger.warning(f"Failed to sync IP {ip_address}: {e}")
    
    def run(self, dry_run: bool = False):
        """Run the synchronization"""
        logger.info("=" * 60)
        logger.info("Starting Karaganda DC VMware Hypervisors Synchronization")
        logger.info("=" * 60)
        
        if not self.connect():
            logger.error("Failed to establish connections")
            return False
        
        try:
            # Get Karaganda VMware hypervisors
            hypervisors = self.get_karaganda_hypervisors()
            self.stats['total'] = len(hypervisors)
            
            if not hypervisors:
                logger.warning("No VMware hypervisors found in DC-Karaganda")
                return True
            
            logger.info(f"Processing {self.stats['total']} VMware hypervisors...")
            
            # Sync each device
            for host in hypervisors:
                if dry_run:
                    hostname = host.get('host', '')
                    inventory = host.get('inventory', {})
                    if isinstance(inventory, dict):
                        logger.info(f"[DRY RUN] Would sync: {hostname}")
                        logger.info(f"  - Visible Name: {host.get('name', 'N/A')}")
                        logger.info(f"  - Vendor: {inventory.get('vendor', 'Unknown')}")
                        logger.info(f"  - Model: {inventory.get('model', inventory.get('hardware', 'Unknown'))}")
                        logger.info(f"  - OS: {inventory.get('os', 'Unknown')}")
                        logger.info(f"  - Role: {self._determine_device_role(hostname)}")
                        
                        # Show IP
                        primary_ip = self._get_primary_ip(host.get('interfaces', []))
                        if primary_ip:
                            logger.info(f"  - Primary IP: {primary_ip}")
                else:
                    self.sync_device(host)
            
            # Print statistics
            logger.info("=" * 60)
            logger.info("Synchronization Complete")
            logger.info(f"Total devices: {self.stats['total']}")
            logger.info(f"Created: {self.stats['created']}")
            logger.info(f"Updated: {self.stats['updated']}")
            logger.info(f"Failed: {self.stats['failed']}")
            logger.info(f"Skipped: {self.stats['skipped']}")
            logger.info("=" * 60)
            
            return True
            
        except Exception as e:
            logger.error(f"Synchronization failed: {e}")
            return False
        
        finally:
            # Disconnect
            if self.zabbix:
                try:
                    self.zabbix.user.logout()
                except:
                    pass
            logger.info("Disconnected")


def main():
    """Main entry point"""
    # Load environment variables
    load_dotenv()
    
    # Get credentials from environment
    zabbix_url = os.getenv('ZABBIX_URL', 'http://zabbix-cloud.ttc.kz/')
    zabbix_user = os.getenv('ZABBIX_USER')
    zabbix_pass = os.getenv('ZABBIX_PASSWORD')
    netbox_url = os.getenv('NETBOX_URL', 'https://web-netbox.t-cloud.kz/')
    netbox_token = os.getenv('NETBOX_TOKEN')
    
    # Validate credentials
    if not all([zabbix_user, zabbix_pass, netbox_token]):
        logger.error("Missing credentials. Please check .env file")
        logger.error("Required: ZABBIX_USER, ZABBIX_PASSWORD, NETBOX_TOKEN")
        return
    
    # Create synchronizer
    sync = KaragandaDCSync(
        zabbix_url=zabbix_url,
        zabbix_user=zabbix_user,
        zabbix_pass=zabbix_pass,
        netbox_url=netbox_url,
        netbox_token=netbox_token
    )
    
    # Run synchronization
    # Start with dry run to test
    import sys
    dry_run = '--dry-run' in sys.argv or '-d' in sys.argv
    
    if dry_run:
        logger.info("Running in DRY RUN mode (no changes will be made)")
    
    success = sync.run(dry_run=dry_run)
    
    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()