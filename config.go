/*
   Zabbix -> NetBox synchronization tool
   Copyright (C) 2025  SUSE LLC <georg.pfuetzenreuter@suse.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type SyncConfig struct {
	UnidentifiableManufacturers []string `yaml:"unidentifiable_manufacturers"`
}

type Config struct {
	NetBox     string     `yaml:"netbox"`
	Zabbix     string     `yaml:"zabbix"`
	HostGroups []string   `yaml:"hostgroups"`
	Sync       SyncConfig `yaml:"sync"`
}

func readConfig(configPath string) (*Config, error) {
	buffer, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("Could not read configuration file: %s", err)
	}

	config := new(Config)
	err = yaml.Unmarshal(buffer, &config)
	if err != nil {
		return nil, fmt.Errorf("Could not parse configuration file: %s", err)
	}

	if config.NetBox == "" || config.Zabbix == "" {
		return nil, fmt.Errorf("Configuration keys 'netbox' and 'zabbix' are required.")
	}

	if config.HostGroups == nil {
		return nil, fmt.Errorf("Configuration key 'hostgroups' is required, set empty array to disable filtering.")
	}

	return config, nil
}
