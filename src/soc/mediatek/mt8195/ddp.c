/* SPDX-License-Identifier: GPL-2.0-only OR MIT */

#include <console/console.h>
#include <device/mmio.h>
#include <edid.h>
#include <soc/addressmap.h>
#include <soc/ddp.h>

#define MERGE_MODE	6
#define MERGE_SWAP	0

static void disp_config_main_path_connection(void)
{
	/* ovl0 */
	write32(&mmsys_cfg->mmsys_ovl_mout_en,
		DISP_OVL0_TO_DISP_RDMA0);
	write32(&mmsys_cfg->mmsys_sel_in,
		SEL_IN_DSC_WRAP0_IN_FROM_DISP_DITHER0 |
		SEL_IN_VPP_MERGE_FROM_DSC_WRAP0_OUT |
		SEL_IN_DP_INTF0_FROM_VPP_MERGE);
	write32(&mmsys_cfg->mmsys_sel_out,
		SEL_OUT_DISP_DITHER0_TO_DSC_WRAP0_IN |
		SEL_OUT_DSC_WRAP0_OUT_TO_VPP_MERGE |
		SEL_OUT_VPP_MERGE_TO_DP_INTF0);
}

static void disp_config_main_path_mutex(void)
{
	write32(&disp_mutex->mutex[0].mod, MUTEX_MOD_MAIN_PATH);

	/* Clock source from DP_INTF0 */
	write32(&disp_mutex->mutex[0].ctl,
		MUTEX_SOF_DP_INTF0 | (MUTEX_SOF_DP_INTF0 << 7));
	write32(&disp_mutex->mutex[0].en, BIT(0));
}

static void ovl_bgclr_in_sel(u32 idx)
{
	setbits32(&disp_ovl[idx]->datapath_con, BIT(2));
}

static void ovl_layer_smi_id_en(u32 idx)
{
	setbits32(&disp_ovl[idx]->datapath_con, BIT(0));
}

static void ovl_layer_gclast_en(u32 idx)
{
	setbits32(&disp_ovl[idx]->datapath_con, BIT(24));
	setbits32(&disp_ovl[idx]->datapath_con, BIT(25));
}

static void ovl_layer_output_clamp_en(u32 idx)
{
	setbits32(&disp_ovl[idx]->datapath_con, BIT(26));
}

static void ccorr_config(u32 width, u32 height)
{
	struct disp_ccorr_regs *const regs = disp_ccorr;

	write32(&regs->size, width << 16 | height);
	clrsetbits32(&regs->cfg, PQ_ENGINE_EN, PQ_RELAY_MODE);
	write32(&regs->en, PQ_EN);
}

static void aal_config(u32 width, u32 height)
{
	struct disp_aal_regs *const regs = disp_aal;

	write32(&regs->size, width << 16 | height);
	write32(&regs->output_size, width << 16 | height);
	clrsetbits32(&regs->cfg, PQ_ENGINE_EN, PQ_RELAY_MODE);
	write32(&regs->en, PQ_EN);
}

static void gamma_config(u32 width, u32 height)
{
	struct disp_gamma_regs *const regs = disp_gamma;

	write32(&regs->size, width << 16 | height);
	setbits32(&regs->cfg, PQ_RELAY_MODE);
	write32(&regs->en, PQ_EN);
}

static void dither_config(u32 width, u32 height)
{
	struct disp_dither_regs *const regs = disp_dither;
	write32(&regs->size, width << 16 | height);
	setbits32(&regs->cfg, PQ_RELAY_MODE);
	write32(&regs->en, PQ_EN);
}

static void dsc_config(void)
{
	struct disp_dsc_regs *const regs = disp_dsc;

	/* Enable dsc bypass mode. */
	write32(&regs->con, DISP_DSC0_CON);
}

static void merge_config(u32 width, u32 height)
{
	struct disp_merge_regs *const regs = disp_merge;

	write32(&regs->cfg0, height << 16 | width);
	write32(&regs->cfg4, height << 16 | width);
	write32(&regs->cfg25, height << 16 | width);
	setbits32(&regs->cfg10, MERGE_SWAP);
	setbits32(&regs->cfg12, MERGE_MODE);
	write32(&regs->en, 0x1);
}

static void main_disp_path_setup(u32 width, u32 height, u32 vrefresh)
{
	u32 idx = 0;
	u32 pixel_clk = width * height * vrefresh;

	for (idx = 0; idx < MAIN_PATH_OVL_NR; idx++) {
		ovl_set_roi(idx, width, height, idx ? 0 : 0xff0000ff);
		ovl_layer_smi_id_en(idx);
		ovl_layer_gclast_en(idx);
		ovl_layer_output_clamp_en(idx);
	}

	rdma_config(width, height, pixel_clk, 5 * KiB);
	color_start(width, height);
	ccorr_config(width, height);
	aal_config(width, height);
	gamma_config(width, height);
	dither_config(width, height);
	dsc_config();
	merge_config(width, height);
	disp_config_main_path_connection();
	disp_config_main_path_mutex();
}

static void disp_clock_on(void)
{
	clrbits32(&mmsys_cfg->mmsys_cg_con0, CG_CON0_DISP_ALL);
	clrbits32(&mmsys_cfg->mmsys_cg_con1, CG_CON1_DISP_ALL);
	clrbits32(&mmsys_cfg->mmsys_cg_con2, CG_CON2_DISP_ALL);
}

void mtk_ddp_init(void)
{
	disp_clock_on();

	/* Turn off M4U port. */
	write32((void *)(SMI_LARB0 + SMI_LARB_PORT_L0_OVL_RDMA0), 0);
}

void mtk_ddp_mode_set(const struct edid *edid)
{
	u32 fmt = OVL_INFMT_RGBA8888;
	u32 bpp = edid->framebuffer_bits_per_pixel / 8;
	u32 width = edid->mode.ha;
	u32 height = edid->mode.va;
	u32 vrefresh = edid->mode.refresh;

	printk(BIOS_DEBUG, "%s: display resolution: %dx%d@%d bpp %d\n",
	       __func__, width, height, vrefresh, bpp);

	if (!vrefresh) {
		if (!width || !height)
			vrefresh = 60;
		else
			vrefresh = edid->mode.pixel_clock * 1000 /
				   ((width + edid->mode.hbl) *
				    (height + edid->mode.vbl));

		printk(BIOS_WARNING, "%s: vrefresh is not provided; using %d\n",
		       __func__, vrefresh);
	}

	main_disp_path_setup(width, height, vrefresh);
	rdma_start();
	ovl_layer_config(fmt, bpp, width, height);
	ovl_bgclr_in_sel(1);
}
