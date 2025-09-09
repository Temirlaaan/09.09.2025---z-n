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
	"flag"
	"log/slog"
	"os"
)

var (
	logger *slog.Logger
)

func main() {
	var configPath string
	var logLevelStr string
	var limit string
	var runDry bool
	var runWet bool

	flag.StringVar(&configPath, "config", "./config.yaml", "Path to configuration file")
	flag.StringVar(&logLevelStr, "loglevel", "info", "Logging level")
	flag.StringVar(&limit, "limit", "", "Host to limit the sync to")
	flag.BoolVar(&runDry, "dry", false, "Run without performing any changes")
	flag.BoolVar(&runWet, "wet", false, "Run and perform changes")
	flag.Parse()

	logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: convertLogLevel(logLevelStr)}))

	config, err := readConfig(configPath)
	if err != nil {
		Fatal("%s", err)
	}

	if runDry && runWet {
		Fatal("Specify -dry OR -wet, not both.")
	}

	if !runDry && !runWet {
		Fatal("Specify -dry OR -wet.")
	}

	var netboxToken string
	var zabbixUser string
	var zabbixPassphrase string

	netboxToken = os.Getenv("NETBOX_TOKEN")
	zabbixUser = os.Getenv("ZABBIX_USER")
	zabbixPassphrase = os.Getenv("ZABBIX_PASSPHRASE")

	if zabbixUser == "" {
		zabbixUser = "guest"
	}

	z := zConnect(config.Zabbix, zabbixUser, zabbixPassphrase)
	nb, nbctx := nbConnect(config.NetBox, netboxToken)

	zh := make(zabbixHosts)
	prepare(z, &zh, config.HostGroups, limit)
	sync(&zh, nb, nbctx, runDry, limit, config.Sync)
}
