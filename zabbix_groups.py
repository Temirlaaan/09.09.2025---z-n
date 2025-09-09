#!/usr/bin/env python3
import os
from pyzabbix import ZabbixAPI
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
zabbix_url = os.getenv('ZABBIX_URL', 'http://zabbix-cloud.ttc.kz/')
zabbix_user = os.getenv('ZABBIX_USER')
zabbix_pass = os.getenv('ZABBIX_PASSWORD')

zabbix = ZabbixAPI(zabbix_url)
zabbix.session.verify = False
zabbix.login(zabbix_user, zabbix_pass)

groups = zabbix.hostgroup.get(output=['groupid', 'name'], sortfield='name')
logger.info(f"Found {len(groups)} host groups:")
for group in groups:
    logger.info(f"  - ID: {group['groupid']}, Name: {group['name']}")