/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef MAINBOARD_GPIO_H
#define MAINBOARD_GPIO_H

#include <soc/gpe.h>
#include <soc/gpio.h>

/* EC in RW */
#define GPIO_EC_IN_RW		GPP_C6

/* BIOS Flash Write Protect */
#define GPIO_PCH_WP		GPP_C23

/* Memory configuration board straps */
#define GPIO_MEM_CONFIG_0	GPP_C12
#define GPIO_MEM_CONFIG_1	GPP_C13
#define GPIO_MEM_CONFIG_2	GPP_C14
#define GPIO_MEM_CONFIG_3	GPP_C15

/* EC wake is LAN_WAKE# which is a special DeepSX wake pin */
#define GPE_EC_WAKE		GPE0_LAN_WAK

/* GPP_B16 is WLAN_WAKE. GPP_B group is routed to DW0 in the GPE0 block */
#define GPE_WLAN_WAKE		GPE0_DW0_16

/* Input device interrupt configuration */
#define TOUCHPAD_INT_L		GPP_B3_IRQ
#define TOUCHSCREEN_INT_L	GPP_E7_IRQ
#define MIC_INT_L		GPP_F10_IRQ

/* GPP_E16 is EC_SCI_L. GPP_E group is routed to DW2 in the GPE0 block */
#define EC_SCI_GPI		GPE0_DW2_16
#define EC_SMI_GPI		GPP_E15

/* Power rail control signals. */
#define EN_PP3300_KEPLER	GPP_C11
#define EN_PP3300_DX_TOUCH	GPP_C22
#define EN_PP3300_DX_EMMC	GPP_D5
#define EN_PP1800_DX_EMMC	GPP_D6
#define EN_PP3300_DX_CAM	GPP_D12

#ifndef __ACPI__
/* Pad configuration in ramstage. */
static const struct pad_config gpio_table[] = {
/* RCIN# */		PAD_CFG_NF(GPP_A0, NONE, DEEP, NF1),
/* LAD0 */		PAD_CFG_NF(GPP_A1, UP_20K, DEEP, NF1),
/* LAD1 */		PAD_CFG_NF(GPP_A2, UP_20K, DEEP, NF1),
/* LAD2 */		PAD_CFG_NF(GPP_A3, UP_20K, DEEP, NF1),
/* LAD3 */		PAD_CFG_NF(GPP_A4, UP_20K, DEEP, NF1),
/* LFRAME# */		PAD_CFG_NF(GPP_A5, NONE, DEEP, NF1),
/* SERIRQ */		PAD_CFG_NF(GPP_A6, NONE, DEEP, NF1),
/* PIRQA# */		/* GPP_A7 */
/* CLKRUN# */		PAD_CFG_NF(GPP_A8, NONE, DEEP, NF1),
/* CLKOUT_LPC0 */	PAD_CFG_NF(GPP_A9, NONE, DEEP, NF1),
/* CLKOUT_LPC1 */	/* GPP_A10 */
/* PME# */		/* GPP_A11 */
/* BM_BUSY# */		/* GPP_A12 */
/* SUSWARN# */		PAD_CFG_NF(GPP_A13, NONE, DEEP, NF1),
/* SUS_STAT# */		PAD_CFG_NF(GPP_A14, NONE, DEEP, NF1),
/* SUSACK# */		PAD_CFG_NF(GPP_A15, NONE, DEEP, NF1),
/* SD_1P8_SEL */	PAD_CFG_NF(GPP_A16, NONE, DEEP, NF1),
/* SD_PWR_EN# */	PAD_CFG_NF(GPP_A17, NONE, DEEP, NF1),
/* ISH_GP0 */		/* GPP_A18 */
/* ISH_GP1 */		/* GPP_A19 */
/* ISH_GP2 */		/* GPP_A20 */
/* ISH_GP3 */		/* GPP_A21 */
/* ISH_GP4 */		/* GPP_A22 */
/* ISH_GP5 */		/* GPP_A23 */
/* CORE_VID0 */		/* GPP_B0 */
/* CORE_VID1 */		/* GPP_B1 */
/* VRALERT# */		/* GPP_B2 */
/* CPU_GP2 */		PAD_CFG_GPI_APIC_HIGH(GPP_B3, NONE, DEEP), /* TRACKPAD */
/* CPU_GP3 */		/* GPP_B4 */
/* SRCCLKREQ0# */	/* GPP_B5 */
/* SRCCLKREQ1# */	PAD_CFG_NF(GPP_B6, NONE, DEEP, NF1), /* WLAN */
/* SRCCLKREQ2# */	PAD_CFG_NF(GPP_B7, NONE, DEEP, NF1), /* KEPLER */
/* SRCCLKREQ3# */	/* GPP_B8 */
/* SRCCLKREQ4# */	/* GPP_B9 */
/* SRCCLKREQ5# */	/* GPP_B10 */
/* EXT_PWR_GATE# */	PAD_CFG_NF(GPP_B11, NONE, DEEP, NF1),
/* SLP_S0# */		PAD_CFG_NF(GPP_B12, NONE, DEEP, NF1),
/* PLTRST# */		PAD_CFG_NF(GPP_B13, NONE, DEEP, NF1),
/* SPKR */		/* GPP_B14 */
/* GSPI0_CS# */		/* GPP_B15 */
/* GSPI0_CLK */		PAD_CFG_GPI_SCI(GPP_B16, NONE, DEEP, EDGE_SINGLE, INVERT), /* WLAN WAKE */
/* GSPI0_MISO */	/* GPP_B17 */
/* GSPI0_MOSI */	/* GPP_B18 */
/* GSPI1_CS# */		/* GPP_B19 */
/* GSPI1_CLK */		/* GPP_B20 */
/* GSPI1_MISO */	/* GPP_B21 */
/* GSPI1_MOSI */	/* GPP_B22 */
/* SM1ALERT# */		PAD_CFG_GPO(GPP_B23, 0, DEEP),
/* SMBCLK */		PAD_CFG_NF(GPP_C0, NONE, DEEP, NF1), /* XDP */
/* SMBDATA */		PAD_CFG_NF(GPP_C1, NONE, DEEP, NF1), /* XDP */
/* SMBALERT# */		/* GPP_C2 */
/* SML0CLK */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C3, NONE, DEEP),
/* SML0DATA */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C4, NONE, DEEP),
/* SML0ALERT# */	PAD_CFG_GPO(GPP_C5, 0, DEEP),
/* SM1CLK */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C6, UP_20K,
						DEEP), /* EC_IN_RW */
/* SM1DATA */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C7, NONE, DEEP),
/* UART0_RXD */		/* GPP_C8 */
/* UART0_TXD */		/* GPP_C9 */
/* UART0_RTS# */	/* GPP_C10 */
/* UART0_CTS# */	PAD_CFG_GPO(GPP_C11, 0, DEEP), /* EN_PP3300_KEPLER */
/* UART1_RXD */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C12, NONE,
						DEEP), /* MEM_CONFIG[0] */
/* UART1_TXD */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C13, NONE,
						DEEP), /* MEM_CONFIG[1] */
/* UART1_RTS# */	PAD_CFG_GPI_GPIO_DRIVER(GPP_C14, NONE,
						DEEP), /* MEM_CONFIG[2] */
/* UART1_CTS# */	PAD_CFG_GPI_GPIO_DRIVER(GPP_C15, NONE,
						DEEP), /* MEM_CONFIG[3] */
/* I2C0_SDA */		PAD_CFG_NF(GPP_C16, NONE, DEEP, NF1), /* TOUCHSCREEN */
/* I2C0_SCL */		PAD_CFG_NF(GPP_C17, NONE, DEEP, NF1), /* TOUCHSCREEN */
/* I2C1_SDA */		PAD_CFG_NF(GPP_C18, NONE, DEEP, NF1), /* TRACKPAD */
/* I2C1_SCL */		PAD_CFG_NF(GPP_C19, NONE, DEEP, NF1), /* TRACKPAD */
/* UART2_RXD */		PAD_CFG_NF(GPP_C20, NONE, DEEP, NF1), /* SERVO */
/* UART2_TXD */		PAD_CFG_NF(GPP_C21, NONE, DEEP, NF1), /* SERVO */
/* UART2_RTS# */	PAD_CFG_GPO(GPP_C22, 1, DEEP), /* EN_PP3300_DX_TOUCH */
/* UART2_CTS# */	PAD_CFG_GPI_GPIO_DRIVER(GPP_C23, UP_20K,
						DEEP), /* PCH_WP */
			/* GPP_D0 */
			/* GPP_D1 */
			/* GPP_D2 */
			/* GPP_D3 */
/* FASHTRIG */		/* GPP_D4 */
/* ISH_I2C0_SDA */	PAD_CFG_GPO(GPP_D5, 1, DEEP), /* EN_PP3300_DX_EMMC */
/* ISH_I2C0_SCL */	PAD_CFG_GPO(GPP_D6, 1, DEEP), /* EN_PP1800_DX_EMMC */
/* ISH_I2C1_SDA */	/* GPP_D7 */
/* ISH_I2C1_SCL */	/* GPP_D8 */
			/* GPP_D9 */
			PAD_CFG_GPO(GPP_D10, 1, DEEP), /* USBA_1_ILIM_SEL_L */
			PAD_CFG_GPO(GPP_D11, 1, DEEP), /* USBA_2_ILIM_SEL_L */
			PAD_CFG_GPO(GPP_D12, 1, DEEP), /* EN_PP3300_DX_CAM */
/* ISH_UART0_RXD */	/* GPP_D13 */
/* ISH_UART0_TXD */	/* GPP_D14 */
/* ISH_UART0_RTS# */	/* GPP_D15 */
/* ISH_UART0_CTS# */	/* GPP_D16 */
/* DMIC_CLK1 */		PAD_CFG_NF(GPP_D17, NONE, DEEP, NF1),
/* DMIC_DATA1 */	PAD_CFG_NF(GPP_D18, NONE, DEEP, NF1),
/* DMIC_CLK0 */		PAD_CFG_NF(GPP_D19, NONE, DEEP, NF1),
/* DMIC_DATA0 */	PAD_CFG_NF(GPP_D20, NONE, DEEP, NF1),
			/* GPP_D21 */
			/* GPP_D22 */
/* I2S_MCLK */		PAD_CFG_NF(GPP_D23, NONE, DEEP, NF1),
/* SPI_TPM_IRQ */	PAD_NC(GPP_E0, NONE),
/* SATAXPCIE1 */	/* GPP_E1 */
/* SATAXPCIE2 */	/* GPP_E2 */
/* CPU_GP0 */		/* GPP_E3 */
/* SATA_DEVSLP0 */	/* GPP_E4 */
/* SATA_DEVSLP1 */	/* GPP_E5 */
/* SATA_DEVSLP2 */	/* GPP_E6 */
/* CPU_GP1 */		PAD_CFG_GPI_APIC_HIGH(GPP_E7, NONE, DEEP), /* TOUCHSCREEN */
/* SATALED# */		/* GPP_E8 */
/* USB2_OCO# */		PAD_CFG_NF(GPP_E9, NONE, DEEP, NF1),
/* USB2_OC1# */		PAD_CFG_NF(GPP_E10, NONE, DEEP, NF1),
/* USB2_OC2# */		PAD_CFG_NF(GPP_E11, NONE, DEEP, NF1),
/* USB2_OC3# */		PAD_CFG_NF(GPP_E12, NONE, DEEP, NF1),
/* DDPB_HPD0 */		PAD_CFG_NF(GPP_E13, NONE, DEEP, NF1),
/* DDPC_HPD1 */		PAD_CFG_NF(GPP_E14, NONE, DEEP, NF1),
/* DDPD_HPD2 */		PAD_CFG_GPI_SMI(GPP_E15, NONE, DEEP, EDGE_SINGLE, INVERT), /* EC_SMI_L */
/* DDPE_HPD3 */		PAD_CFG_GPI_SCI(GPP_E16, NONE, DEEP, EDGE_SINGLE, INVERT), /* EC_SCI_L */
/* EDP_HPD */		PAD_CFG_NF(GPP_E17, NONE, DEEP, NF1),
/* DDPB_CTRLCLK */	/* GPP_E18 */
/* DDPB_CTRLDATA */	/* GPP_E19 */
/* DDPC_CTRLCLK */	/* GPP_E20 */
/* DDPC_CTRLDATA */	/* GPP_E21 */
			/* GPP_E22 */
			/* GPP_E23 */
/*
 * The next 4 pads are for bit banging the amplifiers. They are connected
 * together with i2s0 signals. For default behavior of i2s make these
 * gpio inputs.
 */
/* I2S2_SCLK */		PAD_CFG_GPI_GPIO_DRIVER(GPP_F0, NONE, DEEP),
/* I2S2_SFRM */		PAD_CFG_GPI_GPIO_DRIVER(GPP_F1, NONE, DEEP),
/* I2S2_TXD */		PAD_CFG_GPI_GPIO_DRIVER(GPP_F2, NONE, DEEP),
/* I2S2_RXD */		PAD_CFG_GPI_GPIO_DRIVER(GPP_F3, NONE, DEEP),
/* I2C2_SDA */		/* GPP_F4 */
/* I2C2_SCL */		/* GPP_F5 */
/* I2C3_SDA */		/* GPP_F6 */
/* I2C3_SCL */		/* GPP_F7 */
/* I2C4_SDA */		PAD_CFG_NF_1V8(GPP_F8, NONE, DEEP, NF1), /* Amplifiers */
/* I2C4_SCL */		PAD_CFG_NF_1V8(GPP_F9, NONE, DEEP, NF1), /* Amplifiers */
/* I2C5_SDA */		PAD_CFG_GPI_APIC_HIGH(GPP_F10, NONE, DEEP), /* MIC_INT_L */
/* I2C5_SCL */		/* GPP_F11 */
/* EMMC_CMD */		PAD_CFG_NF(GPP_F12, NONE, DEEP, NF1),
/* EMMC_DATA0 */	PAD_CFG_NF(GPP_F13, NONE, DEEP, NF1),
/* EMMC_DATA1 */	PAD_CFG_NF(GPP_F14, NONE, DEEP, NF1),
/* EMMC_DATA2 */	PAD_CFG_NF(GPP_F15, NONE, DEEP, NF1),
/* EMMC_DATA3 */	PAD_CFG_NF(GPP_F16, NONE, DEEP, NF1),
/* EMMC_DATA4 */	PAD_CFG_NF(GPP_F17, NONE, DEEP, NF1),
/* EMMC_DATA5 */	PAD_CFG_NF(GPP_F18, NONE, DEEP, NF1),
/* EMMC_DATA6 */	PAD_CFG_NF(GPP_F19, NONE, DEEP, NF1),
/* EMMC_DATA7 */	PAD_CFG_NF(GPP_F20, NONE, DEEP, NF1),
/* EMMC_RCLK */		PAD_CFG_NF(GPP_F21, NONE, DEEP, NF1),
/* EMMC_CLK */		PAD_CFG_NF(GPP_F22, NONE, DEEP, NF1),
			/* GPP_F23 */
/* SD_CMD */		PAD_CFG_NF(GPP_G0, NONE, DEEP, NF1),
/* SD_DATA0 */		PAD_CFG_NF(GPP_G1, NONE, DEEP, NF1),
/* SD_DATA1 */		PAD_CFG_NF(GPP_G2, NONE, DEEP, NF1),
/* SD_DATA2 */		PAD_CFG_NF(GPP_G3, NONE, DEEP, NF1),
/* SD_DATA3 */		PAD_CFG_NF(GPP_G4, NONE, DEEP, NF1),
/* SD_CD# */		PAD_CFG_NF(GPP_G5, NONE, DEEP, NF1),
/* SD_CLK */		PAD_CFG_NF(GPP_G6, NONE, DEEP, NF1),
/* SD_WP */		PAD_CFG_NF(GPP_G7, NONE, DEEP, NF1),
/* BATLOW# */		/* GPD0 */
/* ACPRESENT */		PAD_CFG_NF(GPD1, NONE, DEEP, NF1),
/* LAN_WAKE# */		PAD_CFG_NF(GPD2, NONE, DEEP, NF1), /* EC_PCH_WAKE_L */
/* PWRBTN# */		PAD_CFG_NF(GPD3, NONE, DEEP, NF1),
/* SLP_S3# */		PAD_CFG_NF(GPD4, NONE, DEEP, NF1),
/* SLP_S4# */		PAD_CFG_NF(GPD5, NONE, DEEP, NF1),
/* SLP_A# */		PAD_CFG_NF(GPD6, NONE, DEEP, NF1),
			/* GPD7 */
/* SUSCLK */		PAD_CFG_NF(GPD8, NONE, DEEP, NF1),
/* SLP_WLAN# */		/* GPD9 */
/* SLP_S5# */		PAD_CFG_NF(GPD10, NONE, DEEP, NF1),
/* LANPHYC */		/* GPD11 */
};

/* Early pad configuration in bootblock */
static const struct pad_config early_gpio_table[] = {
/* SRCCLKREQ2# */	PAD_CFG_NF(GPP_B7, NONE, DEEP, NF1), /* KEPLER */
/* UART0_CTS# */	PAD_CFG_GPO(GPP_C11, 0, DEEP), /* EN_PP3300_KEPLER */
/* GD_UART2_RXD */	PAD_CFG_NF(GPP_C20, NONE, DEEP, NF1),
/* GD_UART2_TXD */	PAD_CFG_NF(GPP_C21, NONE, DEEP, NF1),
/* SM1CLK */		PAD_CFG_GPI_GPIO_DRIVER(GPP_C6, UP_20K,
						DEEP), /* EC_IN_RW */
};

#endif

#endif
