/* SPDX-License-Identifier: GPL-2.0-only OR MIT */

#ifndef SOC_MEDIATEK_MT8195_GPIO_H
#define SOC_MEDIATEK_MT8195_GPIO_H

#include <soc/addressmap.h>
#include <soc/gpio_common.h>
#include <types.h>

enum {
	MAX_GPIO_REG_BITS = 32,
	MAX_GPIO_MODE_PER_REG = 8,
	GPIO_MODE_BITS = 4,
};

#define PIN(id, name, flag, bit, base, offset, \
	    func1, func2, func3, func4, func5, func6, func7) \
	PAD_##name##_ID = id, \
	PAD_##name##_FLAG = flag, \
	PAD_##name##_BIT = bit, \
	PAD_##name##_BASE = base, \
	PAD_##name##_OFFSET = offset, \
	PAD_##name##_FUNC_##func1 = 1, \
	PAD_##name##_FUNC_##func2 = 2, \
	PAD_##name##_FUNC_##func3 = 3, \
	PAD_##name##_FUNC_##func4 = 4, \
	PAD_##name##_FUNC_##func5 = 5, \
	PAD_##name##_FUNC_##func6 = 6, \
	PAD_##name##_FUNC_##func7 = 7

#define GPIO(name) ((gpio_t){ \
		.id = PAD_##name##_ID, \
		.flag = PAD_##name##_FLAG, \
		.bit = PAD_##name##_BIT, \
		.base = PAD_##name##_BASE, \
		.offset = PAD_##name##_OFFSET \
	})

enum {

	PIN(0, GPIO_00, 1, 0, 0x23, 0x60,
	    TP_GPIO0_AO, MSDC2_CMD, TDMIN_MCK, CLKM0,
	    PERSTN_1, IDDIG_1P, DMIC4_CLK),
	PIN(1, GPIO_01, 1, 1, 0x23, 0x60,
	    TP_GPIO1_AO, MSDC2_CLK, TDMIN_DI, CLKM1,
	    CLKREQN_1, USB_DRVVBUS_1P, DMIC4_DAT),
	PIN(2, GPIO_02, 1, 2, 0x23, 0x60,
	    TP_GPIO2_AO, MSDC2_DAT3, TDMIN_LRCK, CLKM2,
	    WAKEN_1, RES6, DMIC2_CLK),
	PIN(3, GPIO_03, 1, 3, 0x23, 0x60,
	    TP_GPIO3_AO, MSDC2_DAT0, TDMIN_BCK, CLKM3,
	    RES5, RES6, DMIC2_DAT),
	PIN(4, GPIO_04, 1, 4, 0x23, 0x60,
	    TP_GPIO4_AO, MSDC2_DAT2, SPDIF_IN1, UTXD3,
	    SDA2, RES6, IDDIG_2P),
	PIN(5, GPIO_05, 1, 5, 0x23, 0x60,
	    TP_GPIO5_AO, MSDC2_DAT1, SPDIF_IN0, URXD3,
	    SCL2, RES6, USB_DRVVBUS_2P),
	PIN(6, GPIO_06, 0, 0, 0x23, 0x70,
	    TP_GPIO6_AO, DP_TX_HPD, I2SO1_D4, UTXD4,
	    CMVREF3, RES6, DMIC3_CLK),
	PIN(7, GPIO_07, 0, 1, 0x23, 0x70,
	    TP_GPIO7_AO, EDP_TX_HPD, I2SO1_D5, URXD4,
	    CMVREF4, RES6, DMIC3_DAT),
	PIN(8, SDA0, 0, 7, 0x23, 0x70,
	    SDA0, PWM_0, RES3, SPDIF_OUT,
	    RES5, LVTS_FOUT, DBG_MON_A0),
	PIN(9, SCL0, 0, 2, 0x23, 0x70,
	    SCL0, PWM_1, RES3, IR_IN,
	    RES5, LVTS_SDO, DBG_MON_A1),
	PIN(10, SDA1, 0, 8, 0x23, 0x70,
	    SDA1, PWM_2, ADSP_URXD0, SPDIF_IN1,
	    RES5, LVTS_SCF, DBG_MON_A2),
	PIN(11, SCL1, 0, 3, 0x23, 0x70,
	    SCL1, PWM_3, ADSP_UTXD0, SPDIF_IN0,
	    RES5, LVTS_SCK, DBG_MON_A3),
	PIN(12, SDA2, 0, 9, 0x23, 0x70,
	    SDA2, DMIC3_DAT_R, I2SO1_D6, RES4,
	    RES5, LVTS_SDI, DBG_MON_A4),
	PIN(13, SCL2, 0, 4, 0x23, 0x70,
	    SCL2, DMIC4_DAT_R, I2SO1_D7, RES4,
	    RES5, RES6, DBG_MON_A5),
	PIN(14, SDA3, 0, 10, 0x23, 0x70,
	    SDA3, DMIC3_DAT, TDMIN_MCK, RES4,
	    RES5, RES6, DBG_MON_A6),
	PIN(15, SCL3, 0, 5, 0x23, 0x70,
	    SCL3, DMIC3_CLK, TDMIN_DI, RES4,
	    RES5, RES6, DBG_MON_A7),
	PIN(16, SDA4, 0, 11, 0x23, 0x70,
	    SDA4, DMIC4_DAT, TDMIN_LRCK, RES4,
	    RES5, RES6, DBG_MON_A8),
	PIN(17, SCL4, 0, 6, 0x23, 0x70,
	    SCL4, DMIC4_CLK, TDMIN_BCK, RES4,
	    RES5, RES6, DBG_MON_A9),
	PIN(18, DPTX_HPD, 0, 5, 0x10, 0x60,
	    DP_TX_HPD, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(19, PCIE_WAKE_N, 0, 12, 0x10, 0x60,
	    WAKEN, SCP_SDA1, MD32_0_JTAG_TCK, ADSP_JTAG0_TCK,
	    SDA6, RES6, RES7),
	PIN(20, PCIE_PERESET_N, 0, 11, 0x10, 0x60,
	    PERSTN, SCP_SCL1, MD32_0_JTAG_TMS, ADSP_JTAG0_TMS,
	    SCL6, RES6, RES7),
	PIN(21, PCIE_CLKREQ_N, 0, 10, 0x10, 0x60,
	    CLKREQN, RES2, MD32_0_JTAG_TDI, ADSP_JTAG0_TDI,
	    SCP_SDA1, RES6, RES7),
	PIN(22, CMMCLK0, 0, 0, 0x10, 0x60,
	    CMMCLK0, PERSTN_1, RES3, RES4,
	    SCP_SCL1, RES6, MD32_0_GPIO0),
	PIN(23, CMMCLK1, 0, 1, 0x10, 0x60,
	    CMMCLK1, CLKREQN_1, SDA4, DMIC1_CLK,
	    SCP_SDA0, RES6, MD32_0_GPIO1),
	PIN(24, CMMCLK2, 0, 2, 0x10, 0x60,
	    CMMCLK2, WAKEN_1, SCL4, DMIC1_DAT,
	    SCP_SCL0, LVTS_26M, MD32_0_GPIO2),
	PIN(25, CMMRST, 0, 4, 0x10, 0x60,
	    CMMRST, CMMCLK3, SPDIF_OUT, SDA6,
	    ADSP_JTAG0_TRSTN, MD32_0_JTAG_TRST, RES7),
	PIN(26, CMMPDN, 0, 3, 0x10, 0x60,
	    CMMPDN, CMMCLK4, IR_IN, SCL6,
	    ADSP_JTAG0_TDO, MD32_0_JTAG_TDO, RES7),
	PIN(27, HDMIRX_HTPLG, 0, 6, 0x10, 0x60,
	    HDMIRX20_HTPLG, CMFLASH0, MD32_0_TXD, TP_UTXD2_AO,
	    SCL7, UCTS2, DBG_MON_A18),
	PIN(28, HDMIRX_PWR5V, 0, 7, 0x10, 0x60,
	    HDMIRX20_PWR5V, CMFLASH1, MD32_0_RXD, TP_URXD2_AO,
	    SDA7, URTS2, DBG_MON_A19),
	PIN(29, HDMIRX_SCL, 0, 8, 0x10, 0x60,
	    HDMIRX20_SCL, CMFLASH2, SCL5, TP_URTS2_AO,
	    RES5, UTXD2, DBG_MON_A20),
	PIN(30, HDMIRX_SDA, 0, 9, 0x10, 0x60,
	    HDMIRX20_SDA, CMFLASH3, SDA5, TP_UCTS2_AO,
	    RES5, URXD2, DBG_MON_A21),
	PIN(31, HDMITX_PWR5V, 0, 13, 0x21, 0xa0,
	    HDMITX20_PWR5V, DMIC1_DAT_R, PERSTN, RES4,
	    RES5, RES6, DBG_MON_A22),
	PIN(32, HDMITX_HTPLG, 0, 12, 0x21, 0xa0,
	    HDMITX20_HTPLG, RES2, CLKREQN, RES4,
	    RES5, RES6, DBG_MON_A23),
	PIN(33, HDMITX_CEC, 0, 11, 0x21, 0xa0,
	    HDMITX20_CEC, CMVREF0, WAKEN, RES4,
	    RES5, RES6, RES7),
	PIN(34, HDMITX_SCL, 0, 14, 0x21, 0xa0,
	    HDMITX20_SCL, CMVREF1, SCL7, SCL6,
	    RES5, RES6, DBG_MON_A24),
	PIN(35, HDMITX_SDA, 0, 15, 0x21, 0xa0,
	    HDMITX20_SDA, CMVREF2, SDA7, SDA6,
	    RES5, RES6, DBG_MON_A25),
	PIN(36, PMIC_RTC32K_CK, 0, 3, 0x21, 0xb0,
	    RTC32K_CK, RES2, RES3, RES4,
	    RES5, RES6, DBG_MON_A27),
	PIN(37, PMIC_WATCHDOG, 0, 6, 0x21, 0xb0,
	    WATCHDOG, RES2, RES3, RES4,
	    RES5, RES6, DBG_MON_A28),
	PIN(38, PMIC_SRCLKEN_IN0, 0, 4, 0x21, 0xb0,
	    SRCLKENA0, RES2, RES3, RES4,
	    RES5, RES6, DBG_MON_A29),
	PIN(39, PMIC_SRCLKEN_IN1, 0, 5, 0x21, 0xb0,
	    SRCLKENA1, DMIC2_DAT_R, RES3, RES4,
	    RES5, RES6, DBG_MON_A30),
	PIN(40, PWRAP_SPI_CSN, 0, 8, 0x21, 0xb0,
	    PWRAP_SPI0_CSN, RES2, SPIM3_CSB, RES4,
	    RES5, RES6, DBG_MON_A31),
	PIN(41, PWRAP_SPI_CK, 0, 7, 0x21, 0xb0,
	    PWRAP_SPI0_CK, RES2, SPIM3_CLK, RES4,
	    RES5, RES6, DBG_MON_A32),
	PIN(42, PWRAP_SPI_MO, 0, 10, 0x21, 0xb0,
	    PWRAP_SPI0_MO, PWRAP_SPI0_MI, SPIM3_MO, RES4,
	    RES5, RES6, DBG_MON_B0),
	PIN(43, PWRAP_SPI_MI, 0, 9, 0x21, 0xb0,
	    PWRAP_SPI0_MI, PWRAP_SPI0_MO, SPIM3_MI, RES4,
	    RES5, RES6, DBG_MON_B1),
	PIN(44, SPMI_M_SCL, 0, 21, 0x21, 0xb0,
	    SPMI_M_SCL, I2SI00_DATA1, SCL5, UTXD5,
	    RES5, RES6, DBG_MON_B2),
	PIN(45, SPMI_M_SDA, 0, 22, 0x21, 0xb0,
	    SPMI_M_SDA, I2SI00_DATA2, SDA5, URXD5,
	    RES5, RES6, DBG_MON_B3),
	PIN(46, I2SIN_MCK, 0, 18, 0x21, 0xa0,
	    I2SIN_MCK, I2SI00_DATA3, SPLIN_MCK, RES4,
	    RES5, RES6, DBG_MON_B4),
	PIN(47, I2SIN_BCK, 0, 16, 0x21, 0xa0,
	    I2SIN_BCK, I2SIN0_BCK, SPLIN_LRCK, RES4,
	    RES5, RES6, DBG_MON_B5),
	PIN(48, I2SIN_WS, 0, 19, 0x21, 0xa0,
	    I2SIN_WS, I2SIN0_LRCK, SPLIN_BCK, RES4,
	    RES5, RES6, DBG_MON_B6),
	PIN(49, I2SIN_D0, 0, 17, 0x21, 0xa0,
	    I2SIN_D0, I2SI00_DATA0, SPLIN_D0, RES4,
	    RES5, RES6, DBG_MON_B7),
	PIN(50, I2SO1_MCK, 0, 25, 0x21, 0xa0,
	    I2SO1_MCK, I2SI5_D0, RES3, I2SO4_MCK,
	    RES5, RES6, DBG_MON_B8),
	PIN(51, I2SO1_BCK, 0, 20, 0x21, 0xa0,
	    I2SO1_BCK, I2SI5_BCK, RES3, RES4,
	    RES5, RES6, DBG_MON_B9),
	PIN(52, I2SO1_WS, 0, 26, 0x21, 0xa0,
	    I2SO1_WS, I2SI5_WS, RES3, RES4,
	    RES5, RES6, DBG_MON_B10),
	PIN(53, I2SO1_D0, 0, 21, 0x21, 0xa0,
	    I2SO1_D0, I2SI5_MCK, RES3, RES4,
	    RES5, RES6, DBG_MON_B11),
	PIN(54, I2SO1_D1, 0, 22, 0x21, 0xa0,
	    I2SO1_D1, I2SI01_DATA1, SPLIN_D1, I2SO4_BCK,
	    RES5, RES6, DBG_MON_B12),
	PIN(55, I2SO1_D2, 0, 23, 0x21, 0xa0,
	    I2SO1_D2, I2SI01_DATA2, SPLIN_D2, I2SO4_WS,
	    RES5, RES6, DBG_MON_B13),
	PIN(56, I2SO1_D3, 0, 24, 0x21, 0xa0,
	    I2SO1_D3, I2SI01_DATA3, SPLIN_D3, I2SO4_D0,
	    RES5, RES6, DBG_MON_B14),
	PIN(57, I2SO2_MCK, 0, 29, 0x21, 0xa0,
	    I2SO2_MCK, I2SO1_D12, LCM1_RST, RES4,
	    RES5, RES6, DBG_MON_B15),
	PIN(58, I2SO2_BCK, 0, 27, 0x21, 0xa0,
	    I2SO2_BCK, I2SO1_D13, I2SIN1_BCK, RES4,
	    RES5, RES6, DBG_MON_B16),
	PIN(59, I2SO2_WS, 0, 30, 0x21, 0xa0,
	    I2SO2_WS, I2SO1_D14, I2SIN1_LRCK, RES4,
	    RES5, RES6, DBG_MON_B17),
	PIN(60, I2SO2_D0, 0, 28, 0x21, 0xa0,
	    I2SO2_D0, I2SO1_D15, I2SI01_DATA0, RES4,
	    RES5, RES6, DBG_MON_B18),
	PIN(61, DMIC1_SCK, 0, 8, 0x21, 0xa0,
	    DMIC1_CLK, I2SO2_BCK, SCP_SPI2_CK, RES4,
	    RES5, RES6, DBG_MON_B19),
	PIN(62, DMIC1_DAT, 0, 7, 0x21, 0xa0,
	    DMIC1_DAT, I2SO2_WS, SCP_SPI2_MI, RES4,
	    RES5, RES6, DBG_MON_B20),
	PIN(63, DMIC2_SCK, 0, 10, 0x21, 0xa0,
	    DMIC2_CLK, VBUSVALID, SCP_SPI2_MO, SCP_SCL2,
	    SCP_JTAG1_TDO, JTDO_SEL1, DBG_MON_B21),
	PIN(64, DMIC2_DAT, 0, 9, 0x21, 0xa0,
	    DMIC2_DAT, VBUSVALID_1P, SCP_SPI2_CS, SCP_SDA2,
	    RES5, RES6, DBG_MON_B22),
	PIN(65, PCM_DO, 0, 1, 0x21, 0xb0,
	    PCM_DO, AUXIF_ST0, UCTS2, RES4,
	    SCP_JTAG1_TMS, JTMS_SEL1, DBG_MON_B23),
	PIN(66, PCM_CLK, 0, 31, 0x21, 0xa0,
	    PCM_CLK, AUXIF_CLK0, URTS2, RES4,
	    SCP_JTAG1_TCK, JTCK_SEL1, DBG_MON_B24),
	PIN(67, PCM_DI, 0, 0, 0x21, 0xb0,
	    PCM_DI, AUXIF_ST1, UTXD2, RES4,
	    SCP_JTAG1_TRSTN, JTRSTn_SEL1, DBG_MON_B25),
	PIN(68, PCM_SYNC, 0, 2, 0x21, 0xb0,
	    PCM_SYNC, AUXIF_CLK1, URXD2, RES4,
	    SCP_JTAG1_TDI, JTDI_SEL1, DBG_MON_B26),
	PIN(69, AUD_CLK_MOSI, 0, 0, 0x21, 0xa0,
	    AUD_CLK_MOSI, I2SIN2_BCK, PWM_0, WAKEN,
	    RES5, RES6, DBG_MON_B27),
	PIN(70, AUD_SYNC_MOSI, 0, 6, 0x21, 0xa0,
	    AUD_SYNC_MOSI, I2SIN2_LRCK, PWM_1, PERSTN,
	    RES5, RES6, DBG_MON_B28),
	PIN(71, AUD_DAT_MOSI0, 0, 4, 0x21, 0xa0,
	    AUD_DAT_MOSI0, IDDIG_2P, PWM_2, CLKREQN,
	    RES5, RES6, DBG_MON_B29),
	PIN(72, AUD_DAT_MOSI1, 0, 5, 0x21, 0xa0,
	    AUD_DAT_MOSI1, USB_DRVVBUS_2P, PWM_3, PERSTN_1,
	    RES5, RES6, DBG_MON_B30),
	PIN(73, AUD_DAT_MISO0, 0, 1, 0x21, 0xa0,
	    AUD_DAT_MISO0, I2SI02_DATA0, RES3, CLKREQN_1,
	    VOW_DAT_MISO, RES6, DBG_MON_B31),
	PIN(74, AUD_DAT_MISO1, 0, 2, 0x21, 0xa0,
	    AUD_DAT_MISO1, I2SI02_DATA1, RES3, WAKEN_1,
	    VOW_CLK_MISO, RES6, DBG_MON_B32),
	PIN(75, AUD_DAT_MISO2, 0, 3, 0x21, 0xa0,
	    AUD_DAT_MISO2, I2SI02_DATA2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(76, SCP_VREQ_VAO, 0, 11, 0x21, 0xb0,
	    SCP_VREQ_VAO, I2SI02_DATA3, RES3, RES4,
	    RES5, RES6, DBG_MON_A26),
	PIN(77, DGI_D0, 1, 1, 0x22, 0x60,
	    DGI_D0, DPI_D0, I2SI4_MCK, SPIM4_CLK,
	    GBE_TXD3, SPM_JTAG_TCK, RES7),
	PIN(78, DGI_D1, 1, 2, 0x22, 0x60,
	    DGI_D1, DPI_D1, I2SI4_BCK, SPIM4_MO,
	    GBE_TXD2, SPM_JTAG_TMS, RES7),
	PIN(79, DGI_D2, 1, 9, 0x22, 0x60,
	    DGI_D2, DPI_D2, I2SI4_WS, SPIM4_CSB,
	    GBE_TXD1, SPM_JTAG_TDI, RES7),
	PIN(80, DGI_D3, 1, 10, 0x22, 0x60,
	    DGI_D3, DPI_D3, I2SI4_D0, SPIM4_MI,
	    GBE_TXD0, SPM_JTAG_TDO, RES7),
	PIN(81, DGI_D4, 1, 11, 0x22, 0x60,
	    DGI_D4, DPI_D4, I2SI5_MCK, SPIM5_CLK,
	    GBE_RXD3, SPM_JTAG_TRSTN, RES7),
	PIN(82, DGI_D5, 1, 12, 0x22, 0x60,
	    DGI_D5, DPI_D5, I2SI5_BCK, SPIM5_MO,
	    GBE_RXD2, MCUPM_JTAG_TDO, RES7),
	PIN(83, DGI_D6, 1, 13, 0x22, 0x60,
	    DGI_D6, DPI_D6, I2SI5_WS, SPIM5_CSB,
	    GBE_RXD1, MCUPM_JTAG_TMS, RES7),
	PIN(84, DGI_D7, 1, 14, 0x22, 0x60,
	    DGI_D7, DPI_D7, I2SI5_D0, SPIM5_MI,
	    GBE_RXD0, MCUPM_JTAG_TCK, RES7),
	PIN(85, DGI_D8, 1, 15, 0x22, 0x60,
	    DGI_D8, DPI_D8, I2SO4_MCK, SCP_SPI1_B_CK,
	    GBE_TXC, MCUPM_JTAG_TDI, RES7),
	PIN(86, DGI_D9, 1, 16, 0x22, 0x60,
	    DGI_D9, DPI_D9, I2SO4_BCK, SCP_SPI1_B_MI,
	    GBE_RXC, MCUPM_JTAG_TRSTN, RES7),
	PIN(87, DGI_D10, 1, 3, 0x22, 0x60,
	    DGI_D10, DPI_D10, I2SO4_WS, SCP_SPI1_B_CS,
	    GBE_RXDV, SSPM_JTAG_TDO, RES7),
	PIN(88, DGI_D11, 1, 4, 0x22, 0x60,
	    DGI_D11, DPI_D11, I2SO4_D0, SCP_SPI1_B_MO,
	    GBE_TXEN, SSPM_JTAG_TMS, RES7),
	PIN(89, DGI_D12, 1, 5, 0x22, 0x60,
	    DGI_D12, DPI_D12, MSDC2_CMD_A, I2SO5_BCK,
	    GBE_MDC, SSPM_JTAG_TCK, RES7),
	PIN(90, DGI_D13, 1, 6, 0x22, 0x60,
	    DGI_D13, DPI_D13, MSDC2_CLK_A, I2SO5_WS,
	    GBE_MDIO, SSPM_JTAG_TDI, RES7),
	PIN(91, DGI_D14, 1, 7, 0x22, 0x60,
	    DGI_D14, DPI_D14, MSDC2_DAT3_A, I2SO5_D0,
	    GBE_TXER, SSPM_JTAG_TRSTN, RES7),
	PIN(92, DGI_D15, 1, 8, 0x22, 0x60,
	    DGI_D15, DPI_D15, MSDC2_DAT0_A, I2SO2_D1,
	    GBE_RXER, CCU0_JTAG_TDO, RES7),
	PIN(93, DGI_HSYNC, 1, 18, 0x22, 0x60,
	    DGI_HSYNC, DPI_HSYNC, MSDC2_DAT2_A, I2SO2_D2,
	    GBE_COL, CCU0_JTAG_TMS, RES7),
	PIN(94, DGI_VSYNC, 1, 19, 0x22, 0x60,
	    DGI_VSYNC, DPI_VSYNC, MSDC2_DAT1_A, I2SO2_D3,
	    GBE_INTR, CCU0_JTAG_TDI, RES7),
	PIN(95, DGI_DE, 1, 17, 0x22, 0x60,
	    DGI_DE, DPI_DE, UTXD2, RES4,
	    I2SIN_D1, CCU0_JTAG_TCK, RES7),
	PIN(96, DGI_CK, 1, 0, 0x22, 0x60,
	    DGI_CK, DPI_CK, URXD2, I2SO5_MCK,
	    I2SIN_D2, CCU0_JTAG_TRST, RES7),
	PIN(97, DISP_PWM0, 0, 0, 0x22, 0x70,
	    DISP_PWM0, DVFSRC_EXT_REQ, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(98, UART0_TXD, 0, 4, 0x22, 0x70,
	    UTXD0, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(99, UART0_RXD, 0, 3, 0x22, 0x70,
	    URXD0, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(100, UART1_RTS, 0, 6, 0x22, 0x70,
	    URTS1, DSI_TE, I2SO1_D8, KPROW2,
	    PWM_0, TP_URTS1_AO, I2SIN_D0),
	PIN(101, UART1_CTS, 0, 5, 0x22, 0x70,
	    UCTS1, DSI1_TE, I2SO1_D9, KPCOL2,
	    PWM_1, TP_UCTS1_AO, I2SIN_D1),
	PIN(102, UART1_TXD, 0, 8, 0x22, 0x70,
	    UTXD1, VBUSVALID_2P, I2SO1_D10, SSPM_UTXD_AO,
	    TP_UTXD1_AO, MD32_1_TXD, I2SIN_D2),
	PIN(103, UART1_RXD, 0, 7, 0x22, 0x70,
	    URXD1, VBUSVALID_3P, I2SO1_D11, SSPM_URXD_AO,
	    TP_URXD1_AO, MD32_1_RXD, I2SIN_D3),
	PIN(104, KPROW0, 1, 22, 0x22, 0x60,
	    KPROW0, DISP_PWM1, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(105, KPROW1, 1, 23, 0x22, 0x60,
	    KPROW1, EDP_TX_HPD, PWM_2, RES4,
	    RES5, RES6, RES7),
	PIN(106, KPCOL0, 1, 20, 0x22, 0x60,
	    KPCOL0, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(107, KPCOL1, 1, 21, 0x22, 0x60,
	    KPCOL1, DSI1_TE, PWM_3, SCP_SCL3,
	    I2SIN_MCK, RES6, RES7),
	PIN(108, DSI_LCM_RST, 0, 2, 0x22, 0x70,
	    LCM_RST, KPCOL1, RES3, SCP_SDA3,
	    I2SIN_BCK, RES6, RES7),
	PIN(109, DSI_DSI_TE, 0, 1, 0x22, 0x70,
	    DSI_TE, I2SIN_D3, RES3, RES4,
	    I2SIN_WS, RES6, RES7),
	PIN(110, MSDC1_CMD, 1, 1, 0x14, 0x20,
	    MSDC1_CMD, JTMS_SEL3, UDI_TMS, RES4,
	    CCU1_JTAG_TMS, IPU_JTAG_TMS, RES7),
	PIN(111, MSDC1_CLK, 1, 0, 0x14, 0x20,
	    MSDC1_CLK, JTCK_SEL3, UDI_TCK, RES4,
	    CCU1_JTAG_TCK, IPU_JTAG_TCK, RES7),
	PIN(112, MSDC1_DAT0, 1, 2, 0x14, 0x20,
	    MSDC1_DAT0, JTDI_SEL3, UDI_TDI, I2SO2_D0,
	    CCU1_JTAG_TDI, IPU_JTAG_TDI, RES7),
	PIN(113, MSDC1_DAT1, 1, 3, 0x14, 0x20,
	    MSDC1_DAT1, JTDO_SEL3, UDI_TDO, I2SO2_D1,
	    CCU1_JTAG_TDO, IPU_JTAG_TDO, RES7),
	PIN(114, MSDC1_DAT2, 1, 4, 0x14, 0x20,
	    MSDC1_DAT2, JTRSTn_SEL3, UDI_NTRST, I2SO2_D2,
	    CCU1_JTAG_TRST, IPU_JTAG_TRST, RES7),
	PIN(115, MSDC1_DAT3, 1, 5, 0x14, 0x20,
	    MSDC1_DAT3, RES2, RES3, I2SO2_D3,
	    RES5, MD32_1_GPIO2, RES7),
	PIN(116, EMMC_DAT7, 1, 9, 0x25, 0x50,
	    MSDC0_DAT7, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(117, EMMC_DAT6, 1, 8, 0x25, 0x50,
	    MSDC0_DAT6, RES2, RES3, RES4, RES5, RES6, RES7),
	PIN(118, EMMC_DAT5, 1, 7, 0x25, 0x50,
	    MSDC0_DAT5, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(119, EMMC_DAT4, 1, 6, 0x25, 0x50,
	    MSDC0_DAT4, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(120, EMMC_RSTB, 1, 11, 0x25, 0x50,
	    MSDC0_RSTB, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(121, EMMC_CMD, 1, 1, 0x25, 0x50,
	    MSDC0_CMD, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(122, EMMC_CLK, 1, 0, 0x25, 0x50,
	    MSDC0_CLK, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(123, EMMC_DAT3, 1, 5, 0x25, 0x50,
	    MSDC0_DAT3, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(124, EMMC_DAT2, 1, 4, 0x25, 0x50,
	    MSDC0_DAT2, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(125, EMMC_DAT1, 1, 3, 0x25, 0x50,
	    MSDC0_DAT1, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(126, EMMC_DAT0, 1, 2, 0x25, 0x50,
	    MSDC0_DAT0, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(127, EMMC_DSL, 1, 10, 0x25, 0x50,
	    MSDC0_DSL, RES2, RES3, RES4,
	    RES5, RES6, RES7),
	PIN(128, USB_IDDIG, 0, 11, 0x22, 0x70,
	    IDDIG, UCTS2, UTXD5, UFS_MPHY_SCL,
	    mbistreaden_trigger, MD32_1_GPIO0, SCP_SCL2),
	PIN(129, USB_DRV_VBUS, 0, 9, 0x22, 0x70,
	    SB_DRVVBUS, URTS2, URXD5, UFS_MPHY_SDA,
	    mbistwriteen_trigger, MD32_1_GPIO1, SCP_SDA2),
	PIN(130, USB_IDDIG_1P, 0, 12, 0x22, 0x70,
	    IDDIG_1P, SPINOR_IO2, SNFI_WP, VPU_UDI_NTRST,
	    RES5, RES6, RES7),
	PIN(131, USB_DRV_VBUS_1P, 0, 10, 0x22, 0x70,
	    USB_DRVVBUS_1P, SPINOR_IO3, SNFI_HOLD, MD32_1_JTAG_TRST,
	    SCP_JTAG0_TRSTN, APU_JTAG_TRST, RES7),
	PIN(132, SPIM0_CSB, 0, 1, 0x25, 0x60,
	    SPIM0_CSB, SCP_SPI0_CS, SPIS0_CSB, VPU_UDI_TMS,
	    RES5, I2SO5_D0, RES7),
	PIN(133, SPIM0_CLK, 0, 0, 0x25, 0x60,
	    SPIM0_CLK, SCP_SPI0_CK, SPIS0_CLK, VPU_UDI_TCK,
	    RES5, I2SO5_BCK, RES7),
	PIN(134, SPIM0_MO, 0, 3, 0x25, 0x60,
	    SPIM0_MO, SCP_SPI0_MO, SPIS0_SI, VPU_UDI_TDO,
	    RES5, I2SO5_WS, RES7),
	PIN(135, SPIM0_MI, 0, 2, 0x25, 0x60,
	    SPIM0_MI, SCP_SPI0_MI, SPIS0_SO, VPU_UDI_TDI,
	    RES5, I2SO5_MCK, RES7),
	PIN(136, SPIM1_CSB, 0, 14, 0x21, 0xb0,
	    SPIM1_CSB, SCP_SPI1_A_CS, SPIS1_CSB, MD32_1_JTAG_TMS,
	    SCP_JTAG0_TMS, APU_JTAG_TMS, DBG_MON_A15),
	PIN(137, SPIM1_CLK, 0, 13, 0x21, 0xb0,
	    SPIM1_CLK, SCP_SPI1_A_CK, SPIS1_CLK, MD32_1_JTAG_TCK,
	    SCP_JTAG0_TCK, APU_JTAG_TCK, DBG_MON_A14),
	PIN(138, SPIM1_MO, 0, 16, 0x21, 0xb0,
	    SPIM1_MO, SCP_SPI1_A_MO, SPIS1_SI, MD32_1_JTAG_TDO,
	    SCP_JTAG0_TDO, APU_JTAG_TDO, DBG_MON_A16),
	PIN(139, SPIM1_MI, 0, 15, 0x21, 0xb0,
	    SPIM1_MI, SCP_SPI1_A_MI, SPIS1_SO, MD32_1_JTAG_TDI,
	    SCP_JTAG0_TDI, APU_JTAG_TDI, DBG_MON_A17),
	PIN(140, SPIM2_CSB, 0, 18, 0x21, 0xb0,
	    SPIM2_CSB, SPINOR_CS, SNFI_CS, DMIC3_DAT,
	    RES5, RES6, DBG_MON_A11),
	PIN(141, SPIM2_CLK, 0, 17, 0x21, 0xb0,
	    SPIM2_CLK, SPINOR_CK, SNFI_CLK, DMIC3_CLK,
	    RES5, RES6, DBG_MON_A10),
	PIN(142, SPIM2_MO, 0, 20, 0x21, 0xb0,
	    SPIM2_MO, SPINOR_IO0, SNFI_MOSI, DMIC4_DAT,
	    RES5, RES6, DBG_MON_A12),
	PIN(143, SPIM2_MI, 0, 19, 0x21, 0xb0,
	    PIM2_MI, SPINOR_IO1, SNFI_MISO, DMIC4_CLK,
	    RES5, RES6, DBG_MON_A13),
};

struct val_regs {
	uint32_t val;
	uint32_t set;
	uint32_t rst;
	uint32_t align;
};

struct gpio_regs {
	struct val_regs dir[7];
	uint8_t rsv00[144];
	struct val_regs dout[7];
	uint8_t rsv01[144];
	struct val_regs din[7];
	uint8_t rsv02[144];
	struct val_regs mode[28];
	uint8_t rsv03[560];
	uint32_t dram_pinmux_trapping;
};

check_member(gpio_regs, mode[27].val, 0x4b0);
check_member(gpio_regs, dram_pinmux_trapping, 0x6f0);

static struct gpio_regs *const mtk_gpio = (void *)(GPIO_BASE);

#endif
