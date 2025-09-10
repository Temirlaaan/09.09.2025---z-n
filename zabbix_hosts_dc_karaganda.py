#!/usr/bin/env python3
import os
from pyzabbix import ZabbixAPI
from dotenv import load_dotenv
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
zabbix_url = os.getenv('ZABBIX_URL', 'http://zabbix-cloud.ttc.kz/')
zabbix_user = os.getenv('ZABBIX_USER')
zabbix_pass = os.getenv('ZABBIX_PASSWORD')

# Validate credentials
if not all([zabbix_user, zabbix_pass]):
    logger.error("Missing Zabbix credentials. Please check .env file")
    exit(1)

# Connect to Zabbix
try:
    zabbix = ZabbixAPI(zabbix_url)
    zabbix.session.verify = False
    zabbix.login(zabbix_user, zabbix_pass)
    logger.info("Connected to Zabbix API")
except Exception as e:
    logger.error(f"Failed to connect to Zabbix: {e}")
    exit(1)

# Fetch hosts from DC-Karaganda (groupid: 1037)
try:
    hosts = zabbix.host.get(
        groupids=['1037'],  # Filter by DC-Karaganda group
        output=['hostid', 'host', 'name', 'status'],  # Basic host fields
        selectInventory=[
            'vendor', 'model', 'os', 'os_short', 'serialno_a', 'hardware', 
            'alias', 'location_lat'
        ],  # Extended inventory details
        selectInterfaces=['ip', 'type'],  # Interface details (e.g., IP addresses)
        selectGroups=['groupid', 'name'],  # Confirm group membership
        selectParentTemplates=['templateid', 'name']  # Templates for VMware detection
    )
    logger.info(f"Found {len(hosts)} hosts in DC-Karaganda (ID: 1037):")
    
    for host in hosts:
        logger.info(f"Host ID: {host['hostid']}")
        logger.info(f"  - Hostname: {host.get('host', 'N/A')}")
        logger.info(f"  - Visible Name: {host.get('name', 'N/A')}")
        logger.info(f"  - Status: {'Active' if host.get('status') == '0' else 'Disabled'}")
        
        # Inventory details
        inventory = host.get('inventory', {})
        if isinstance(inventory, dict):
            logger.info(f"  - Vendor: {inventory.get('vendor', 'N/A')}")
            logger.info(f"  - Model: {inventory.get('model', 'N/A')}")
            logger.info(f"  - OS: {inventory.get('os', 'N/A')}")
            logger.info(f"  - Version: {inventory.get('os_short', 'N/A')}")
            logger.info(f"  - Serial: {inventory.get('serialno_a', 'N/A')}")
            logger.info(f"  - CPU Model: {inventory.get('hardware', 'N/A')}")
            logger.info(f"  - Cluster Name: {inventory.get('alias', 'N/A')}")
            logger.info(f"  - Location Latitude: {inventory.get('location_lat', 'N/A')}")

        # Fetch total memory from items
        try:
            items = zabbix.item.get(
                hostids=[host['hostid']],
                search={'key_': 'vm.memory.size[total]'},  # Replace with correct key from debug
                output=['lastvalue']
            )
            total_memory = items[0].get('lastvalue', 'N/A') if items else 'N/A'
            if total_memory != 'N/A':
                try:
                    total_memory_value = float(total_memory) / (1024 ** 4)  # Convert bytes to TB
                    total_memory = f"{total_memory_value:.2f} TB"
                except (ValueError, TypeError):
                    pass  # Keep as is if not convertible
            logger.info(f"  - Total Memory: {total_memory}")
        except Exception as e:
            logger.error(f"Failed to fetch total memory for host {host['hostid']}: {e}")
            logger.info(f"  - Total Memory: N/A")

        # Interfaces (e.g., IPs)
        interfaces = host.get('interfaces', [])
        if interfaces:
            logger.info("  - Interfaces:")
            for iface in interfaces:
                ip = iface.get('ip', 'N/A')
                if_type = iface.get('type', 'N/A')
                logger.info(f"    - IP: {ip}, Type: {if_type}")

        # Groups
        groups = host.get('groups', [])
        if groups:
            logger.info("  - Groups:")
            for group in groups:
                logger.info(f"    - {group.get('name')} (ID: {group.get('groupid')})")

        # Templates
        templates = host.get('parentTemplates', [])
        if templates:
            logger.info("  - Templates:")
            for template in templates:
                logger.info(f"    - {template.get('name')} (ID: {template.get('templateid')})")
        logger.info("-" * 50)

except Exception as e:
    logger.error(f"Failed to fetch hosts: {e}")
finally:
    try:
        zabbix.user.logout()
        logger.info("Disconnected from Zabbix")
    except:
        pass