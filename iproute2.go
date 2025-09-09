/*
   iproute2 JSON parser
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
	"encoding/json"
	"fmt"
	"strings"
)

type iproute2AddrInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Prefixlen int    `json:"prefixlen"`
	Label     string `json:"label"`
}

type iproute2SlaveData struct {
	State      string `json:"state"`
	MiiStatus  string `json:"mii_status"`
	PermHwAddr string `json:"perm_hwaddr"`
}

type iproute2LinkInfo struct {
	Kind    string          `json:"info_kind"`
	DataRaw json.RawMessage `json:"info_data"`
	Data    interface{}
}

type iproute2LinkInfoDataBond struct {
	Mode string `json:"mode"`
}

type iproute2LinkInfoDataBridge struct {
	VlanProtocol string `json:"vlan_protocol"`
	BridgeId     string `json:"bridge_id"`
}

type iproute2LinkInfoDataVlan struct {
	Protocol string `json:"protocol"`
	Id       int32  `json:"id"`
}

type ipRoute2Interface struct {
	IfName    string             `json:"ifname"`
	Mtu       int32              `json:"mtu"`
	OperState string             `json:"operstate"`
	LinkType  string             `json:"link_type"`
	Address   string             `json:"address"`
	AddrInfo  []iproute2AddrInfo `json:"addr_info"`
	LinkInfo  iproute2LinkInfo   `json:"linkinfo"`
}

type ipRoute2Interfaces []*ipRoute2Interface

func (infs ipRoute2Interfaces) String() string {
	var out []string
	for _, inf := range infs {
		out = append(out, fmt.Sprintf("%v", *inf))
	}
	return strings.Join(out[:], "")
}

func parseIpRoute2AddressData(raw string) *ipRoute2Interface {
	if raw == "" {
		return nil
	}
	// too old iproute2
	if raw == "Option \"-j\" is unknown, try \"ip -help\"." {
		return nil
	}

	inf := new(ipRoute2Interface)
	err := json.Unmarshal([]byte(raw), &inf)
	handleError("Parsing interface JSON", err)

	if inf.LinkInfo.DataRaw != nil {
		switch inf.LinkInfo.Kind {
		case "bond":
			inf.LinkInfo.Data = iproute2LinkInfoDataBond{}
		case "bridge":
			inf.LinkInfo.Data = iproute2LinkInfoDataBridge{}
		case "vlan":
			inf.LinkInfo.Data = iproute2LinkInfoDataVlan{}
		case "":
			return nil
		default:
			Error("Unhandled kind %s", inf.LinkInfo.Kind)
			return nil
		}

		err = json.Unmarshal(inf.LinkInfo.DataRaw, &inf.LinkInfo.Data)
		handleError("Parsing link data JSON", err)

		// raw data is no longer needed, reset field to avoid huge debug output
		inf.LinkInfo.DataRaw = nil
	}

	Debug("Got data %+v", inf)

	return inf
}

func convertInterfaces(in ipRoute2Interfaces) []linuxInterface {
	out := make([]linuxInterface, len(in))
	for _, iinf := range in {
		linf := linuxInterface{}

		linf.Name = iinf.IfName

		if iinf.LinkType == "ether" {
			linf.Type = 1
		}

		for _, addr := range iinf.AddrInfo {
			linf.Addresses = append(linf.Addresses, fmt.Sprintf("%s/%d", addr.Local, addr.Prefixlen))
		}

		out = append(out, linf)
	}

	return out
}
