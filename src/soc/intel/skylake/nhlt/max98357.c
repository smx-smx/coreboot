/* SPDX-License-Identifier: GPL-2.0-only */

#include <commonlib/bsd/helpers.h>
#include <soc/nhlt.h>

static const struct nhlt_format_config max98357_render_formats[] = {
	/* 48 KHz 24-bits per sample. */
	{
		.num_channels = 2,
		.sample_freq_khz = 48,
		.container_bits_per_sample = 32,
		.valid_bits_per_sample = 24,
		.speaker_mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT,
		.settings_file = "max98357-render-2ch-48khz-24b.bin",
	},
};

static const struct nhlt_endp_descriptor max98357_descriptors[] = {
	{
		.link = NHLT_LINK_SSP,
		.device = NHLT_SSP_DEV_I2S,
		.direction = NHLT_DIR_RENDER,
		.vid = NHLT_VID,
		.did = NHLT_DID_SSP,
		.formats = max98357_render_formats,
		.num_formats = ARRAY_SIZE(max98357_render_formats),
	},
};

int nhlt_soc_add_max98357(struct nhlt *nhlt, int hwlink)
{
	/* Virtual bus id of SSP links are the hardware port ids proper. */
	return nhlt_add_ssp_endpoints(nhlt, hwlink, max98357_descriptors,
					ARRAY_SIZE(max98357_descriptors));
}
