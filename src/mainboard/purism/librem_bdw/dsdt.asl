/* SPDX-License-Identifier: GPL-2.0-only */

#include <acpi/acpi.h>
DefinitionBlock(
	"dsdt.aml",
	"DSDT",
	ACPI_DSDT_REV_2,
	OEM_ID,
	ACPI_TABLE_CREATOR,
	0x20160115	/* OEM revision */
)
{
	#include <acpi/dsdt_top.asl>
	#include <soc/intel/broadwell/acpi/platform.asl>
	#include <soc/intel/broadwell/pch/acpi/globalnvs.asl>
	#include <cpu/intel/common/acpi/cpu.asl>

	Scope (\_SB) {
		Device (PCI0)
		{
			#include <northbridge/intel/haswell/acpi/hostbridge.asl>
			#include <soc/intel/broadwell/pch/acpi/pch.asl>
			#include <drivers/intel/gma/acpi/default_brightness_levels.asl>
		}
	}

	#include <southbridge/intel/common/acpi/sleepstates.asl>

	#include "acpi/mainboard.asl"
}
