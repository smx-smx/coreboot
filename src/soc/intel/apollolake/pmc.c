/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "chip.h"
#include <console/console.h>
#include <device/mmio.h>
#include <device/device.h>
#include <device/pci.h>
#include <intelblocks/pmc.h>
#include <intelblocks/pmclib.h>
#include <soc/iomap.h>
#include <soc/pm.h>
#include <timer.h>

/* Fill up PMC resource structure */
int pmc_soc_get_resources(struct pmc_resource_config *cfg)
{
	cfg->pwrmbase_offset = PCI_BASE_ADDRESS_0;
	cfg->pwrmbase_addr = PCH_PWRM_BASE_ADDRESS;
	cfg->pwrmbase_size = PMC_BAR0_SIZE;
	cfg->abase_offset = PCI_BASE_ADDRESS_4;
	cfg->abase_addr = ACPI_BASE_ADDRESS;
	cfg->abase_size = ACPI_BASE_SIZE;

	return 0;
}

static int choose_slp_s3_assertion_width(int width_usecs)
{
	int i;
	static const struct {
		int max_width;
		int value;
	} slp_s3_settings[] = {
		{
			.max_width = 60,
			.value = SLP_S3_ASSERT_60_USEC,
		},
		{
			.max_width = 1 * USECS_PER_MSEC,
			.value = SLP_S3_ASSERT_1_MSEC,
		},
		{
			.max_width = 50 * USECS_PER_MSEC,
			.value = SLP_S3_ASSERT_50_MSEC,
		},
		{
			.max_width =  2 * USECS_PER_SEC,
			.value = SLP_S3_ASSERT_2_SEC,
		},
	};

	for (i = 0; i < ARRAY_SIZE(slp_s3_settings); i++) {
		if (width_usecs <= slp_s3_settings[i].max_width)
			break;
	}

	/* Provide conservative default if nothing set in devicetree
	 * or requested assertion width too large. */
	if (width_usecs <= 0 || i == ARRAY_SIZE(slp_s3_settings))
		i = ARRAY_SIZE(slp_s3_settings) - 1;

	printk(BIOS_DEBUG, "SLP S3 assertion width: %d usecs\n",
		slp_s3_settings[i].max_width);

	return slp_s3_settings[i].value;
}

static void set_slp_s3_assertion_width(int width_usecs)
{
	uint32_t reg;
	uintptr_t gen_pmcon3 = soc_read_pmc_base() + GEN_PMCON3;
	int setting = choose_slp_s3_assertion_width(width_usecs);

	reg = read32p(gen_pmcon3);
	reg &= ~SLP_S3_ASSERT_MASK;
	reg |= setting << SLP_S3_ASSERT_WIDTH_SHIFT;
	write32p(gen_pmcon3, reg);
}

void pmc_soc_init(struct device *dev)
{
	const struct soc_intel_apollolake_config *cfg = config_of(dev);

	/* Set up GPE configuration */
	pmc_gpe_init();
	pmc_set_acpi_mode();

	if (cfg != NULL)
		set_slp_s3_assertion_width(cfg->slp_s3_assertion_width_usecs);

	/* Log power state */
	pch_log_state();

	/* Now that things have been logged clear out the PMC state. */
	pmc_clear_prsts();

	pmc_set_power_failure_state(true);
}
