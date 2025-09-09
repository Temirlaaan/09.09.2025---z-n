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
	"context"
	"fmt"
	"github.com/fabiang/go-zabbix"
	"github.com/netbox-community/go-netbox/v4"
	"strings"
)

func prepare(z *zabbix.Session, zh *zabbixHosts, whitelistedHostgroups []string, limit string) {
	workHosts := getHosts(z, filterHostGroupIds(getHostGroups(z), whitelistedHostgroups))
	hostIds := filterHostIds(workHosts)
	filterHostInterfaces(zh, getHostInterfaces(z, hostIds))

	search := make(map[string][]string)
	search["key_"] = []string{
		"agent.hostname",
		"net.if.ip.a.raw[*]",
		"sys.hw.manufacturer",
		"sys.hw.metadata",
		"sys.hw.chassis_serial",
		"sys.hw.product_serial",
		"sys.hw.model",
		"sys.mount.nfs",
		"sys.net.listen",
		"sys.os.release",
		"system.cpu.num",
		"system.sw.arch",
		"vm.memory.size[total]",
	}

	filterItems(zh, getItems(z, hostIds, search), search["key_"])
	scanHosts(zh, limit)
}

func processSite(name string, sites []site) *site {
	name_parts := strings.Split(name, ".")
	domain_parts := name_parts[len(name_parts)-3:]
	if strings.Contains(domain_parts[0], "-") {
		domain_parts[0] = strings.Split(domain_parts[0], "-")[1]
	}
	domain := strings.Join(domain_parts, ".")

	for _, s := range sites {
		if s.Domain == domain {
			return &s
		}
	}

	return nil
}

func processMacAddress(nb *netbox.APIClient, ctx context.Context, address string, dryRun bool) (int32, bool) {
	// some interface types have an empty MAC address, for example WireGuard ones - behave as if the MAC address already exists
	if address == "" {
		return 0, true
	}

	Debug("Processing MAC address %s", address)
	query, _, err := nb.DcimAPI.DcimMacAddressesList(ctx).MacAddress([]string{address}).Execute()
	handleError("Query of MAC addresses", err)
	found := query.Results
	Debug("Found MAC addresses: %+v", found)

	var objid int32
	var assigned bool

	switch len(found) {
	case 0:
		if dryRun {
			Info("Would create MAC address object '%s'", address)
			return objid, assigned
		}

		Info("Creating MAC address object '%s'", address)

		created, response, rerr := nb.DcimAPI.DcimMacAddressesCreate(ctx).MACAddressRequest(*netbox.NewMACAddressRequest(address)).Execute()
		handleResponse(created, response, rerr)

		objid = created.Id
		assigned = false

	case 1:
		Debug("MAC address object '%s' already exists", address)

		objid = found[0].Id

		if found[0].AssignedObjectType.IsSet() && found[0].AssignedObjectId.IsSet() {
			assigned = true
		}

	default:
		Warn("MAC address object '%s' exists multiple times", address)
	}

	return objid, assigned
}

func processIpAddress(hinf *ipRoute2Interface, nbobjtype string, nbinfid int64, nb *netbox.APIClient, ctx context.Context, dnsname string, dryRun bool) {
	for _, address := range hinf.AddrInfo {
		if isLinkLocal(address.Local) {
			Debug("Skipping link local IP adress %s", address.Local)
			// currently we do not track these in NetBox
			// it might make sense to later add logic to differentiate SLAAC and Privacy addresses
			continue
		}

		cidraddress := fmt.Sprintf("%s/%d", address.Local, address.Prefixlen)

		Debug("Processing IP address %s", cidraddress)

		ipquery, response, err := nb.IpamAPI.IpamIpAddressesList(ctx).Address([]string{cidraddress}).Execute()
		handleResponse(ipquery, response, err)
		handleError("Query of IP addresses", err)
		ipfound := ipquery.Results
		Debug("Found IP addresses: %+v", ipfound)
		foundcount := len(ipfound)

		var found bool
		var ipobjid int32
		var nbipo netbox.IPAddress
		var unassignedcount int

		for _, nbip := range ipfound {
			aobjid := nbip.GetAssignedObjectId()

			if aobjid == nbinfid {
				found = true
				ipobjid = nbip.Id
				nbipo = nbip
				break
			}

			if aobjid == 0 {
				unassignedcount++
				// ipobjid and nbipo can be overwritten here by design
				ipobjid = nbip.Id
				nbipo = nbip
			}
		}

		// found IP address assigned to the desired interface
		//   => update
		// OR
		// found single unassigned IP address
		//   => update and assign
		// OR
		// found multiple unassigned IP addresses
		//   => bail out
		// OR
		// found no IP addresses
		//   => create

		if found || foundcount == 1 {
			request := *netbox.NewPatchedWritableIPAddressRequest()

			if dnsname != "" && dnsname != *nbipo.DnsName {
				Info("DNS Name changed: %s => %s", *nbipo.DnsName, dnsname)
				request.SetDnsName(dnsname)
			}

			if request.HasDnsName() {
				Debug("Payload: %+v", request)

				if dryRun {
					Info("Would patch object")
					continue
				}

				nb.IpamAPI.IpamIpAddressesPartialUpdate(ctx, ipobjid).PatchedWritableIPAddressRequest(request).Execute()
			}
		}

		if foundcount == 1 && unassignedcount == 1 {
			if dryRun {
				Info("Would assign existing IP address object")
				continue
			}

			assignIpAddress(nb, ctx, ipobjid, cidraddress, nbobjtype, nbinfid)

		} else if foundcount > 1 && unassignedcount > 1 {
			Error("Multiple unassigned IP addresses match %s, cannot decide", cidraddress)

		} else if foundcount == 0 && unassignedcount == 0 {
			if dryRun {
				Info("Would create IP address object")
				continue
			}

			Info("Creating IP address object '%s'", cidraddress)

			status, err := netbox.NewPatchedWritableIPAddressRequestStatusFromValue("active")
			if err != nil {
				handleError("Validation of new status value", err)
			}

			request := netbox.WritableIPAddressRequest{
				Address:            cidraddress,
				Status:             status,
				AssignedObjectType: *netbox.NewNullableString(&nbobjtype),
				AssignedObjectId:   *netbox.NewNullableInt64(&nbinfid),
			}

			if dnsname != "" {
				request.SetDnsName(dnsname)
			}

			created, response, rerr := nb.IpamAPI.IpamIpAddressesCreate(ctx).WritableIPAddressRequest(request).Execute()
			handleResponse(created, response, rerr)

		} else if !found {
			Debug("found %v, foundcount %d, unassignedcount %d", found, foundcount, unassignedcount)
			Fatal("processIpAddress() unhandled situation, this should never happen")
		}
	}
}

func processVirtualMachineInterface(host *zabbixHostData, nb *netbox.APIClient, ctx context.Context, vmname string, vmobjid int32, dryRun bool) {
	var iffound []netbox.VMInterface

	if vmobjid > 0 {
		ifquery, response, err := nb.VirtualizationAPI.VirtualizationInterfacesList(ctx).VirtualMachineId([]int32{vmobjid}).Execute()
		handleResponse(ifquery, response, err)
		handleError("Query of virtual machine interfaces", err)
		iffound = ifquery.Results
		Debug("Found virtual machine interfaces: %+v", iffound)
	}

	hinfcount := len(host.Interfaces)
	for _, inf := range host.Interfaces {
		if inf.IfName == "lo" {
			hinfcount = hinfcount - 1
			continue
		}
	}

	var dnsname string

	if hinfcount == 1 {
		dnsname = vmname
	} else {
		// no logic to determine primary interface amongst multiple yet
		dnsname = ""
	}

	for _, inf := range host.Interfaces {
		if inf.IfName == "lo" {
			continue
		}

		mtu := *netbox.NewNullableInt32(&inf.Mtu)

		var found bool
		var intobjid int32
		var nbinf netbox.VMInterface

		Debug("Scanning %+v", inf)
		for _, nbif := range iffound {
			if inf.IfName == nbif.Name {
				// UPDATE
				found = true
				intobjid = nbif.Id
				nbinf = nbif

				break
			}
		}

		macobjid, macassigned := processMacAddress(nb, ctx, inf.Address, dryRun)
		nbmac := *netbox.NewNullableBriefMACAddressRequest(netbox.NewBriefMACAddressRequest(strings.ToUpper(inf.Address)))

		if found {
			request := *netbox.NewPatchedWritableVMInterfaceRequest()

			mac_new := nbmac.Get().GetMacAddress()
			mac_old := nbinf.PrimaryMacAddress.Get().GetMacAddress()
			if mac_new != mac_old {
				Info("Primary MAC address changed: %s => %s", mac_old, mac_new)
				request.PrimaryMacAddress = nbmac
			}

			mtu_new := *mtu.Get()
			mtu_old := *nbinf.Mtu.Get()
			if mtu_new != mtu_old {
				Info("MTU changed: %d => %d", mtu_old, mtu_new)
				request.Mtu = mtu
			}

			// TODO: compare/update tagged VLANs

			if request.HasPrimaryMacAddress() || request.HasMtu() {
				Debug("Payload: %+v", request)

				if dryRun {
					Info("Would patch object")
					continue
				}

				created, response, rerr := nb.VirtualizationAPI.VirtualizationInterfacesPartialUpdate(ctx, intobjid).PatchedWritableVMInterfaceRequest(request).Execute()
				handleResponse(created, response, rerr)
			}

		} else {
			if dryRun {
				Info("Would create interface object")
			} else {
				request := netbox.WritableVMInterfaceRequest{
					VirtualMachine: *netbox.NewBriefVirtualMachineRequest(vmname),
					Name:           inf.IfName,
					Mtu:            mtu,
					TaggedVlans:    *new([]int32),
					Enabled:        netbox.PtrBool(true),
				}

				mode, err := netbox.NewPatchedWritableInterfaceRequestModeFromValue("tagged")
				handleError("Constructing 802.1Q mode from string", err)

				if inf.LinkInfo.Kind == "vlan" {
					request.Mode = *netbox.NewNullablePatchedWritableInterfaceRequestMode(mode)
					request.TaggedVlans = append(request.TaggedVlans, inf.LinkInfo.Data.(iproute2LinkInfoDataVlan).Id)
				}

				created, response, rerr := nb.VirtualizationAPI.VirtualizationInterfacesCreate(ctx).WritableVMInterfaceRequest(request).Execute()
				handleResponse(created, response, rerr)

				intobjid = created.Id

			}
		}

		if macobjid > 0 && !macassigned && !dryRun {
			assignMacAddress(nb, ctx, macobjid, inf.Address, "virtualization.vminterface", int64(intobjid))
		}

		// cannot set PrimaryMacAddress during creation as assignment needs to happen first
		if !found && !dryRun {
			request := netbox.PatchedWritableVMInterfaceRequest{
				PrimaryMacAddress: nbmac,
			}

			created, response, rerr := nb.VirtualizationAPI.VirtualizationInterfacesPartialUpdate(ctx, intobjid).PatchedWritableVMInterfaceRequest(request).Execute()
			handleResponse(created, response, rerr)
		}

		processIpAddress(inf, "virtualization.vminterface", int64(intobjid), nb, ctx, dnsname, dryRun)

	}
}

func processDevice(host *zabbixHostData, nb *netbox.APIClient, ctx context.Context, dryRun bool, config SyncConfig, sitemeta site) {
	name := host.HostName
	query, _, err := nb.DcimAPI.DcimDevicesList(ctx).Name([]string{name}).Limit(2).Execute()
	handleError("Query of devices", err)
	found := query.Results
	Debug("Found devices: %+v", found)
	foundcount := len(found)

	devicemanufacturer := *netbox.NewBriefManufacturerRequest(host.Manufacturer, "")
	devicetype := *netbox.NewBriefDeviceTypeRequest(devicemanufacturer, host.Model, "")
	devicerole := *netbox.NewBriefDeviceRoleRequest("Server", "")
	deviceserial := host.Serial
	devicesite := *netbox.NewBriefSiteRequest(sitemeta.Name, sitemeta.Slug)

	var devobjid int32

	switch foundcount {
	case 0:
		if dryRun {
			Info("Would create device object")
		} else {
			Info("Creating device object")

			status, err := netbox.NewDeviceStatusValueFromValue("active")
			if err != nil {
				handleError("Validation of new status value", err)
			}

			request := netbox.WritableDeviceWithConfigContextRequest{
				Name:       *netbox.NewNullableString(&name),
				DeviceType: devicetype,
				Role:       devicerole,
				Serial:     &deviceserial,
				Site:       devicesite,
				Status:     status,
			}

			Debug("Payload: %+v", request)
			created, response, rerr := nb.DcimAPI.DcimDevicesCreate(ctx).WritableDeviceWithConfigContextRequest(request).Execute()
			handleResponse(created, response, rerr)
			devobjid = created.Id
		}

	case 1:
		object := found[0]

		request := *netbox.NewPatchedWritableDeviceWithConfigContextRequest()

		site_new := devicesite
		site_old := object.Site
		if site_new.GetSlug() != site_old.GetSlug() {
			Info("Site changed by domain: %s (%s) => %s (%s)", site_old.Name, site_old.Slug, site_new.Name, site_new.Slug)
			request.Site = &devicesite
		}

		unidentifiable_manufacturer := false

		devicemanufacturer_new := devicemanufacturer.GetName()
		devicetype_new := devicetype.GetModel()
		devicemanufacturer_old := object.DeviceType.GetManufacturer().Name
		devicetype_old := object.DeviceType.GetModel()
		if contains(config.UnidentifiableManufacturers, devicemanufacturer_old) {
			unidentifiable_manufacturer = true
		}
		if !unidentifiable_manufacturer && (devicemanufacturer_new != devicemanufacturer_old || devicetype_new != devicetype_old) {
			Info("Device type changed: %s %s => %s %s", devicemanufacturer_old, devicetype_old, devicemanufacturer_new, devicetype_new)
			request.DeviceType = &devicetype
		}

		devicerole_new := devicerole.GetName()
		devicerole_old := object.Role.GetName()
		if devicerole_new != devicerole_old {
			Info("Device role changed: %s => %s", devicerole_old, devicerole_new)
			request.Role = &devicerole
		}

		deviceserial_old := *object.Serial
		if !unidentifiable_manufacturer && deviceserial != deviceserial_old {
			Info("Device serial changed: %s => %s", deviceserial_old, deviceserial)
			request.Serial = &deviceserial
		}

		if request.HasSite() || request.HasDeviceType() || request.HasRole() || request.HasSerial() {
			Debug("Payload: %+v", request)

			if dryRun {
				Info("Would patch object")
				return
			}

			created, response, rerr := nb.DcimAPI.DcimDevicesPartialUpdate(ctx, object.Id).PatchedWritableDeviceWithConfigContextRequest(request).Execute()
			handleResponse(created, response, rerr)
			devobjid = created.Id

		} else {
			devobjid = object.Id
		}

	default:
		Error("Host %s matches multiple (%d) objects in NetBox.", name, foundcount)
	}

	Debug("%d", devobjid)

}

func processVirtualMachine(host *zabbixHostData, nb *netbox.APIClient, ctx context.Context, dryRun bool, sitemeta site) {
	name := host.HostName

	query, _, err := nb.VirtualizationAPI.VirtualizationVirtualMachinesList(ctx).Name([]string{name}).Limit(2).Execute()
	handleError("Query of virtual machines", err)
	found := query.Results
	Debug("Found virtual machines: %+v", found)
	foundcount := len(found)

	memory := *netbox.NewNullableInt32(&host.Memory)
	vcpus := *netbox.NewNullableFloat64(&host.CPUs)
	nbsite := *netbox.NewNullableBriefSiteRequest(netbox.NewBriefSiteRequest(sitemeta.Name, sitemeta.Slug))

	var vmobjid int32

	switch foundcount {
	case 0:
		if dryRun {
			Info("Would create virtual machine object")
		} else {
			Info("Creating virtual machine object")

			status, err := netbox.NewInventoryItemStatusValueFromValue("active")
			if err != nil {
				handleError("Validation of new status value", err)
			}

			request := netbox.WritableVirtualMachineWithConfigContextRequest{
				Name:    name,
				Site:    nbsite,
				Cluster: *netbox.NewNullableBriefClusterRequest(netbox.NewBriefClusterRequest("Unmapped")),
				Status:  status,
				Memory:  memory,
				Vcpus:   vcpus,
			}
			Debug("Payload: %+v", request)
			created, response, rerr := nb.VirtualizationAPI.VirtualizationVirtualMachinesCreate(ctx).WritableVirtualMachineWithConfigContextRequest(request).Execute()
			handleResponse(created, response, rerr)
			vmobjid = created.Id
		}

	case 1:
		object := found[0]

		request := *netbox.NewPatchedWritableVirtualMachineWithConfigContextRequest()

		site_new := *nbsite.Get()
		site_old := *object.Site.Get()
		if site_new.Slug != site_old.Slug {
			Info("Site changed by domain: %s (%s) => %s (%s)", site_old.Name, site_old.Slug, site_new.Name, site_new.Slug)
			request.Site = nbsite
		}

		memory_new := *memory.Get()
		var memory_old int32
		if object.Memory.Get() != nil {
			memory_old = *object.Memory.Get()
		}
		if memory_new != memory_old {
			Info("Memory changed: %d => %d", memory_old, memory_new)
			request.Memory = memory
		}

		vcpus_new := *vcpus.Get()
		var vcpus_old float64
		if object.Vcpus.Get() != nil {
			vcpus_old = *object.Vcpus.Get()
		}
		if vcpus_new != vcpus_old {
			Info("vCPUs changed: %f => %f", vcpus_old, vcpus_new)
			request.Vcpus = vcpus
		}

		if request.HasSite() || request.HasMemory() || request.HasVcpus() {
			Debug("Payload: %+v", request)

			if dryRun {
				Info("Would patch object")
				return
			}

			created, response, rerr := nb.VirtualizationAPI.VirtualizationVirtualMachinesPartialUpdate(ctx, object.Id).PatchedWritableVirtualMachineWithConfigContextRequest(request).Execute()
			handleResponse(created, response, rerr)
			vmobjid = created.Id

		} else {
			vmobjid = object.Id
		}

	default:
		Error("Host %s matches multiple (%d) objects in NetBox.", name, foundcount)
	}

	processVirtualMachineInterface(host, nb, ctx, name, vmobjid, dryRun)

}

func sync(zh *zabbixHosts, nb *netbox.APIClient, ctx context.Context, dryRun bool, limit string, config SyncConfig) {
	sites := getSites(nb, ctx)

	for _, host := range *zh {
		name := host.HostName

		if limit != "" && name != limit {
			continue
		}

		if host.Error {
			Debug("Skipping processing of host %s.", host.HostName)
			continue
		}

		sitemeta := processSite(name, sites)

		if sitemeta == nil {
			Debug("Skipping processing of host %s due to unknown site.", host.HostName)
			continue
		}

		Info("Processing host %s", name)

		switch host.ObjType {

		case "Virtual":
			processVirtualMachine(host, nb, ctx, dryRun, *sitemeta)

		case "Physical":
			processDevice(host, nb, ctx, dryRun, config, *sitemeta)
		}
	}
}
