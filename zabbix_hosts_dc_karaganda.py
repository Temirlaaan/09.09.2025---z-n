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
        groupids=['1035'],  # Filter by DC-Karaganda group
        output=['hostid', 'host', 'name', 'status'],  # Basic host fields
        selectInventory=['vendor', 'model', 'os', 'serialno_a', 'hardware'],  # Inventory details
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
            logger.info(f"  - Model: {inventory.get('model', inventory.get('hardware', 'N/A'))}")
            logger.info(f"  - OS: {inventory.get('os', 'N/A')}")
            logger.info(f"  - Serial: {inventory.get('serialno_a', 'N/A')}")

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