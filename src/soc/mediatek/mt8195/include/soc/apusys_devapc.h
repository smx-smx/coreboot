/* SPDX-License-Identifier: GPL-2.0-only OR MIT */

#ifndef APUSYS_DEVAPC_H
#define APUSYS_DEVAPC_H

enum apusys_apc_error {
	APUSYS_APC_OK = 0,
	APUSYS_APC_ERR_GENERIC,
	APUSYS_APC_ERR_INVALID_CMD,
	APUSYS_APC_ERR_SLAVE_TYPE_NOT_SUPPORTED,
	APUSYS_APC_ERR_SLAVE_IDX_NOT_SUPPORTED,
	APUSYS_APC_ERR_DOMAIN_NOT_SUPPORTED,
	APUSYS_APC_ERR_PERMISSION_NOT_SUPPORTED,
	APUSYS_APC_ERR_OUT_OF_BOUNDARY,
	APUSYS_APC_ERR_REQ_TYPE_NOT_SUPPORTED,
};

struct apc_apu_dom_16 {
	unsigned char d_permission[16];
};

#define APUSYS_APC_CON ((void *)(APUSYS_APC_AO_BASE + 0x00F00))
#define APUSYS_SYS0_APC_LOCK_0 ((void *)(APUSYS_APC_AO_BASE + 0x00700))
#define APUSYS_NOC_DAPC_CON ((void *)(APUSYS_NOC_DAPC_AO_BASE + 0x00F00))

#define APU_SCTRL_REVISER BIT(15)
#define DEVAPC_AO_WRAPPER BIT(8)

#define APUSYS_APC_SYS0_AO_SLAVE_NUM_IN_1_DOM 16U
#define APUSYS_APC_SYS0_AO_DOM_NUM 16U
#define APUSYS_APC_SYS0_AO_SLAVE_NUM 71U

#define APUSYS_NOC_DAPC_AO_SLAVE_NUM_IN_1_DOM 16U
#define APUSYS_NOC_DAPC_AO_DOM_NUM 16U
#define APUSYS_NOC_DAPC_AO_SLAVE_NUM 15U

void start_apusys_devapc(void);

#endif /* APUSYS_DEVAPC_H */
