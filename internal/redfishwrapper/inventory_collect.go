package redfishwrapper

import (
	"fmt"
	common2 "github.com/stmcginnis/gofish/common"
	"math"
	"net"
	"strings"

	"github.com/bmc-toolbox/common"
	"github.com/stmcginnis/gofish/redfish"
)

// defines various inventory collection helper methods

// collectEnclosure collects Enclosure information
func (c *Client) collectEnclosure(ch *redfish.Chassis, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	e := &common.Enclosure{
		Common: common.Common{
			Description: ch.Description,
			Vendor:      common.FormatVendorName(ch.Manufacturer),
			Model:       ch.Model,
			Serial:      ch.SerialNumber,
			Status: &common.Status{
				Health: string(ch.Status.Health),
				State:  string(ch.Status.State),
			},
			Firmware: &common.Firmware{},
		},

		ID:          ch.ID,
		ChassisType: string(ch.ChassisType),
	}

	if e.Model == "" && ch.PartNumber != "" {
		e.Model = ch.PartNumber
	}

	// include additional firmware attributes from redfish firmware inventory
	c.firmwareAttributes(common.SlugEnclosure, e.ID, e.Firmware, softwareInventory)

	device.Enclosures = append(device.Enclosures, e)

	return nil
}

// collectPSUs collects Power Supply Unit component information
func (c *Client) collectPSUs(ch *redfish.Chassis, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	power, err := ch.Power()
	if err != nil {
		return err
	}

	if power == nil {
		return nil
	}

	for _, psu := range power.PowerSupplies {
		p := &common.PSU{
			Common: common.Common{
				Description: psu.Name,
				Vendor:      common.FormatVendorName(psu.Manufacturer),
				Model:       psu.Model,
				Serial:      psu.SerialNumber,

				Status: &common.Status{
					Health: string(psu.Status.Health),
					State:  string(psu.Status.State),
				},
				Firmware: &common.Firmware{
					Installed: psu.FirmwareVersion,
				},
			},

			ID:                 psu.ID,
			PowerCapacityWatts: int64(psu.PowerCapacityWatts),
		}

		// include additional firmware attributes from redfish firmware inventory
		c.firmwareAttributes(common.SlugPSU, psu.ID, p.Firmware, softwareInventory)

		device.PSUs = append(device.PSUs, p)

	}
	return nil
}

// collectTPMs collects Trusted Platform Module component information
func (c *Client) collectTPMs(sys *redfish.ComputerSystem, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	for _, module := range sys.TrustedModules {
		tpm := &common.TPM{
			Common: common.Common{
				Firmware: &common.Firmware{
					Installed: module.FirmwareVersion,
				},
				Status: &common.Status{
					State:  string(module.Status.State),
					Health: string(module.Status.Health),
				},
			},

			InterfaceType: string(module.InterfaceType),
		}

		// include additional firmware attributes from redfish firmware inventory
		c.firmwareAttributes(common.SlugTPM, "TPM", tpm.Firmware, softwareInventory)

		device.TPMs = append(device.TPMs, tpm)
	}

	return nil
}

// collectNICs collects network interface component information
func (c *Client) collectNICs(sys *redfish.ComputerSystem, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	if sys == nil || device == nil {
		return nil
	}

	// collect network interface information
	nics, err := sys.NetworkInterfaces()
	if err != nil {
		return err
	}

	// collect network ethernet interface information, these attributes are not available in NetworkAdapter, NetworkInterfaces
	ethernetInterfaces, err := sys.EthernetInterfaces()
	if err != nil {
		return err
	}

	for _, nic := range nics {
		// collect network interface adaptor information
		adapter, err := nic.NetworkAdapter()
		if err != nil {
			return err
		}

		if adapter == nil {
			continue
		}

		n := &common.NIC{
			Common: common.Common{
				Vendor:      common.FormatVendorName(adapter.Manufacturer),
				Model:       adapter.Model,
				Serial:      adapter.SerialNumber,
				ProductName: adapter.PartNumber,
				Status: &common.Status{
					State:  string(nic.Status.State),
					Health: string(nic.Status.Health),
				},
			},

			ID: nic.ID, // "Id": "NIC.Slot.3",
		}

		ports, err := adapter.NetworkPorts()
		if err != nil {
			return err
		}

		portFirmwareVersion := getFirmwareVersionFromController(adapter.Controllers, len(ports))

		for _, networkPort := range ports {

			// populate network ports general data
			nicPort := &common.NICPort{}
			c.collectNetworkPortInfo(nicPort, adapter, networkPort, portFirmwareVersion, softwareInventory)

			if networkPort.ActiveLinkTechnology == redfish.EthernetLinkNetworkTechnology {
				// ethernet specific data
				c.collectEthernetInfo(nicPort, ethernetInterfaces)
			}
			n.NICPorts = append(n.NICPorts, nicPort)
		}

		// include additional firmware attributes from redfish firmware inventory
		c.firmwareAttributes(common.SlugNIC, n.ID, n.Firmware, softwareInventory)
		if len(portFirmwareVersion) > 0 {
			if n.Firmware == nil {
				n.Firmware = &common.Firmware{}
			}
			n.Firmware.Installed = portFirmwareVersion
		}

		device.NICs = append(device.NICs, n)
	}

	return nil
}

func (c *Client) collectNetworkPortInfo(
	nicPort *common.NICPort,
	adapter *redfish.NetworkAdapter,
	networkPort *redfish.NetworkPort,
	firmware string,
	softwareInventory []*redfish.SoftwareInventory,
) {

	if adapter != nil {
		nicPort.Vendor = adapter.Manufacturer
		nicPort.Model = adapter.Model
	}

	if networkPort != nil {

		nicPort.Description = networkPort.Description
		nicPort.PCIVendorID = networkPort.VendorID
		nicPort.Status = &common.Status{
			Health: string(networkPort.Status.Health),
			State:  string(networkPort.Status.State),
		}
		nicPort.ID = networkPort.ID
		nicPort.PhysicalID = networkPort.PhysicalPortNumber
		nicPort.LinkStatus = string(networkPort.LinkStatus)
		nicPort.ActiveLinkTechnology = string(networkPort.ActiveLinkTechnology)

		if networkPort.CurrentLinkSpeedMbps > 0 {
			nicPort.SpeedBits = int64(networkPort.CurrentLinkSpeedMbps) * int64(math.Pow10(6))
		}

		if len(networkPort.AssociatedNetworkAddresses) > 0 {
			for _, macAddress := range networkPort.AssociatedNetworkAddresses {
				macAddress = normalizeMACAddress(macAddress)
				if len(macAddress) > 0 && macAddress != "00:00:00:00:00:00" {
					nicPort.MacAddress = macAddress // first valid value only
					break
				}
			}
		}

		c.firmwareAttributes(common.SlugNIC, networkPort.ID, nicPort.Firmware, softwareInventory)
	}
	if len(firmware) > 0 {
		if nicPort.Firmware == nil {
			nicPort.Firmware = &common.Firmware{}
		}
		nicPort.Firmware.Installed = firmware
	}
}

// changes dashes in MAC address into colons
func normalizeMACAddress(srcMACAddress string) (macAddress string) {
	return strings.Replace(srcMACAddress, "-", ":", -1)
}

func (c *Client) collectEthernetInfo(nicPort *common.NICPort, ethernetInterfaces []*redfish.EthernetInterface) {
	if nicPort == nil {
		return
	}

	// populate mac address et al. from matching ethernet interface
	for _, ethInterface := range ethernetInterfaces {

		macAddress := normalizeMACAddress(ethInterface.MACAddress)
		if len(macAddress) == 0 ||
			macAddress == "00:00:00:00:00:00" ||
			!strings.EqualFold(macAddress, nicPort.MacAddress) {
			continue
		}

		// override values only if needed
		if len(ethInterface.Description) > 0 {
			nicPort.Description = ethInterface.Description
		}
		if len(ethInterface.Status.Health) > 0 {
			if nicPort.Status == nil {
				nicPort.Status = &common.Status{}
			}
			nicPort.Status.Health = string(ethInterface.Status.Health)
		}
		if len(ethInterface.Status.State) > 0 {
			if nicPort.Status == nil {
				nicPort.Status = &common.Status{}
			}
			nicPort.Status.State = string(ethInterface.Status.State)
		}

		if ethInterface.SpeedMbps > 0 {
			nicPort.SpeedBits = int64(ethInterface.SpeedMbps) * int64(math.Pow10(6))
		}

		nicPort.AutoNeg = ethInterface.AutoNeg
		nicPort.MTUSize = ethInterface.MTUSize

		// always override mac address
		nicPort.MacAddress = macAddress

		if len(ethInterface.IPv4Addresses) > 0 {
			if nicPort.IPv4Addresses == nil {
				nicPort.IPv4Addresses = make([]common.IPAddress, 0)
			}
			for _, ipv4Address := range ethInterface.IPv4Addresses {

				if len(ipv4Address.Address) == 0 || ipv4Address.Address == "0.0.0.0" {
					// if ipv4 address is empty, skip
					continue
				}

				nicPort.IPv4Addresses = append(nicPort.IPv4Addresses, common.IPAddress{
					Address:    ipv4Address.Address,
					Gateway:    ipv4Address.Gateway,
					SubnetMask: ipv4Address.SubnetMask,
				})
			}
			for _, ipv6Address := range ethInterface.IPv6Addresses {

				if len(ipv6Address.Address) == 0 {
					// if IP address is empty, skip
					continue
				}

				ipv6 := net.ParseIP(ipv6Address.Address)
				if len(ipv6) == 0 || ipv6.Equal(net.IPv6zero) {
					// if IP address is empty, skip
					continue
				}

				addressData := common.IPAddress{
					Address:    ipv6Address.Address,
					SubnetMask: fmt.Sprintf("%d", ipv6Address.PrefixLength),
				}
				if len(ethInterface.IPv6DefaultGateway) > 0 {
					addressData.Gateway = ethInterface.IPv6DefaultGateway
				}
				nicPort.IPv6Addresses = append(nicPort.IPv6Addresses, addressData)
			}
		}

		break // stop at first match
	}
}

func getFirmwareVersionFromController(controllers []redfish.Controllers, portCount int) string {
	for _, controller := range controllers {
		if controller.ControllerCapabilities.NetworkPortCount == portCount {
			return controller.FirmwarePackageVersion
		}
	}
	return ""
}

func (c *Client) collectBIOS(sys *redfish.ComputerSystem, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	device.BIOS = &common.BIOS{
		Common: common.Common{
			Firmware: &common.Firmware{
				Installed: sys.BIOSVersion,
			},
		},
	}

	bios, err := sys.Bios()
	if err != nil {
		return err
	}

	if bios != nil {
		device.BIOS.Description = bios.Description
	}

	// include additional firmware attributes from redfish firmware inventory
	c.firmwareAttributes(common.SlugBIOS, "BIOS", device.BIOS.Firmware, softwareInventory)

	return nil
}

// collectDrives collects drive component information
func (c *Client) collectDrives(sys *redfish.ComputerSystem, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	storage, err := sys.Storage()
	if err != nil {
		return err
	}

	for _, member := range storage {
		if member.DrivesCount == 0 {
			continue
		}

		drives, err := member.Drives()
		if err != nil {
			return err
		}

		for _, drive := range drives {
			device.Drives = append(device.Drives, i.collectDrive(drive, member.ID))
		}
	}

	return nil
}

func (i *inventory) collectDrive(srcDrive *redfish.Drive, controllerID string) (dstDrive *common.Drive) {
	if srcDrive == nil {
		return
	}

	dstDrive = &common.Drive{
		Common: common.Common{
			ProductName: srcDrive.Name,
			Description: srcDrive.Description,
			Serial:      srcDrive.SerialNumber,
			Vendor:      common.FormatVendorName(srcDrive.Manufacturer),
			Model:       srcDrive.Model,
			Firmware: &common.Firmware{
				Installed: srcDrive.Revision,
			},
			Status: &common.Status{
				Health: string(srcDrive.Status.Health),
				State:  string(srcDrive.Status.State),
			},
		},

		ID:                  srcDrive.ID,
		Type:                string(srcDrive.MediaType),
		StorageController:   controllerID,
		Protocol:            string(srcDrive.Protocol),
		CapacityBytes:       srcDrive.CapacityBytes,
		CapableSpeedGbps:    int64(srcDrive.CapableSpeedGbs),
		NegotiatedSpeedGbps: int64(srcDrive.NegotiatedSpeedGbs),
		BlockSizeBytes:      int64(srcDrive.BlockSizeBytes),
	}

	dstDrive.WWN = getNAAIdentifier(srcDrive.Identifiers)

	// include additional firmware attributes from redfish firmware inventory
	c.firmwareAttributes("Disk", srcDrive.ID, dstDrive.Firmware, softwareInventory)

	return
}

// collectStorageControllers populates the device with Storage controller component attributes
func (c *Client) collectStorageControllers(sys *redfish.ComputerSystem, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	storage, err := sys.Storage()
	if err != nil {
		return err
	}

	for _, member := range storage {
		volumes, err := member.Volumes()
		if err != nil {
			return err
		}

		for _, controller := range member.StorageControllers {

			cs := &common.StorageController{
				Common: common.Common{
					Description: controller.Name,
					Vendor:      common.FormatVendorName(controller.Manufacturer),
					Model:       controller.PartNumber,
					Serial:      controller.SerialNumber,
					Status: &common.Status{
						Health: string(controller.Status.Health),
						State:  string(controller.Status.State),
					},
					Firmware: &common.Firmware{
						Installed: controller.FirmwareVersion,
					},
				},

				ID:        controller.ID,
				SpeedGbps: int64(controller.SpeedGbps),
				Volumes:   []*common.VirtualDisk{},
			}

			c.PhysicalID = getNAAIdentifier(controller.Identifiers)

			// In some cases the storage controller model number is present in the Name field
			if strings.TrimSpace(cs.Model) == "" && strings.TrimSpace(controller.Name) != "" {
				cs.Model = controller.Name
			}

			if len(strings.TrimSpace(c.ID)) == 0 {
				c.ID = member.ID
			}

			for _, volume := range volumes {
				// check if this volume belongs to this RAID controller
				// e.g. volume ID: "Disk.Bay.0:Enclosure.Internal.0-1:RAID.SL.3-1"
				// e.g. RAID controller ID: "RAID.SL.3-1"
				if strings.Contains(volume.ID, ":"+c.ID) {

					v := &common.VirtualDisk{
						ID:             volume.ID,
						Name:           volume.Name,
						RaidType:       string(volume.VolumeType),
						SizeBytes:      int64(volume.CapacityBytes),
						Status:         string(volume.Status.Health),
						PhysicalDrives: []*common.Drive{},
					}
					drives, err := volume.Drives()
					if err != nil {
						return err
					}
					for _, drive := range drives {
						v.PhysicalDrives = append(v.PhysicalDrives, i.collectDrive(drive, member.ID))
					}
					c.Volumes = append(c.Volumes, v)
				}
			}

			// include additional firmware attributes from redfish firmware inventory
			c.firmwareAttributes(cs.Description, cs.ID, cs.Firmware, softwareInventory)

			device.StorageControllers = append(device.StorageControllers, cs)
		}
	}

	return nil
}

func getNAAIdentifier(identifiers []common2.Identifier) string {
	for _, id := range identifiers {
		if strings.EqualFold(string(id.DurableNameFormat), "naa") &&
			len(id.DurableName) > 0 {
			return id.DurableName
		}
	}
	return ""
}

// collectCPUs populates the device with CPU component attributes
func (c *Client) collectCPUs(sys *redfish.ComputerSystem, device *common.Device, _ []*redfish.SoftwareInventory) (err error) {
	procs, err := sys.Processors()
	if err != nil {
		return err
	}

	for _, proc := range procs {
		if proc.ProcessorType != "CPU" {
			// TODO: handle this case
			continue
		}

		device.CPUs = append(device.CPUs, &common.CPU{
			Common: common.Common{
				Description: proc.Description,
				Vendor:      common.FormatVendorName(proc.Manufacturer),
				Model:       proc.Model,
				Serial:      "",
				Status: &common.Status{
					Health: string(proc.Status.Health),
					State:  string(proc.Status.State),
				},
				Firmware: &common.Firmware{
					Installed: proc.ProcessorID.MicrocodeInfo,
				},
			},
			ID:           proc.ID,
			Architecture: string(proc.ProcessorArchitecture),
			Slot:         proc.Socket,
			ClockSpeedHz: int64(proc.MaxSpeedMHz * 1000 * 1000),
			Cores:        proc.TotalCores,
			Threads:      proc.TotalThreads,
		})
	}

	return nil
}

// collectDIMMs populates the device with memory component attributes
func (c *Client) collectDIMMs(sys *redfish.ComputerSystem, device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {
	dimms, err := sys.Memory()
	if err != nil {
		return err
	}

	for _, dimm := range dimms {
		device.Memory = append(device.Memory, &common.Memory{
			Common: common.Common{
				Description: dimm.Description,
				Vendor:      common.FormatVendorName(dimm.Manufacturer),
				Model:       "",
				Serial:      dimm.SerialNumber,
				Status: &common.Status{
					Health: string(dimm.Status.Health),
					State:  string(dimm.Status.State),
				},
			},

			Slot:         dimm.ID,
			Type:         string(dimm.MemoryType),
			SizeBytes:    int64(dimm.VolatileSizeMiB * 1024 * 1024),
			FormFactor:   "",
			PartNumber:   dimm.PartNumber,
			ClockSpeedHz: int64(dimm.OperatingSpeedMhz * 1000 * 1000),
		})
	}

	return nil
}

// collecCPLDs populates the device with CPLD component attributes
func (c *Client) collectCPLDs(device *common.Device, softwareInventory []*redfish.SoftwareInventory) (err error) {

	cpld := &common.CPLD{
		Common: common.Common{
			Vendor:   common.FormatVendorName(device.Vendor),
			Model:    device.Model,
			Firmware: &common.Firmware{Metadata: make(map[string]string)},
		},
	}

	c.firmwareAttributes(common.SlugCPLD, "", cpld.Firmware, softwareInventory)
	name, exists := cpld.Firmware.Metadata["name"]
	if exists {
		cpld.Description = name
	}

	device.CPLDs = []*common.CPLD{cpld}

	return nil
}
