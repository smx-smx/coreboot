/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <baseboard/gpio.h>
#include <baseboard/variants.h>
#include <types.h>
#include <vendorcode/google/chromeos/chromeos.h>

/* Pad configuration in ramstage */
/* Leave eSPI pins untouched from default settings */
static const struct pad_config gpio_table[] = {
	/* A0 thru A4 and A9/10 come configured out of reset, do not touch */
	/* A0  : ESPI_IO0 ==> ESPI_IO_0 */
	/* A1  : ESPI_IO1 ==> ESPI_IO_1 */
	/* A2  : ESPI_IO2 ==> ESPI_IO_2 */
	/* A3  : ESPI_IO3 ==> ESPI_IO_3 */
	/* A4  : ESPI_CS# ==> ESPI_CS_L */
	/* A9  : ESPI_CLK ==> ESPI_CLK */
	/* A10  : ESPI_RESET ==> ESPI_RESET */
	/* A5 : USB_C0_AUXP_DC */
	PAD_CFG_GPO(GPP_A5, 1, DEEP),
	/* A6 : USB_C0_AUXN_DC */
	PAD_CFG_GPO(GPP_A6, 1, DEEP),
	/* A8 : EC_IN_RW_OD */
	PAD_CFG_GPI(GPP_A8, NONE, DEEP),
	/* A11 : SSD_PERST_L */
	PAD_CFG_GPO(GPP_A11, 1, DEEP),
	/* A12 : M2_SSD_PEDET */
	PAD_CFG_NF(GPP_A12, NONE, DEEP, NF1),
	/* A13 : BT_DISABLE_L */
	PAD_CFG_GPO(GPP_A13, 1, DEEP),
	/* A14 : USB_OC1# ==> USB_A0_OC_ODL */
	PAD_CFG_NF(GPP_A14, NONE, DEEP, NF1),
	/* A15 : USB_OC2# ==> USB_A1_OC_ODL */
	PAD_CFG_NF(GPP_A15, NONE, DEEP, NF1),
	/* A16 : USB_C0_OC_ODL */
	PAD_CFG_NF(GPP_A16, NONE, DEEP, NF1),
	/* A17 : DDSP_HPDC ==> MEM_CH_SEL */
	PAD_CFG_GPI(GPP_A17, NONE, DEEP),
	/* A18 : HDMI_HPD */
	PAD_CFG_NF(GPP_A18, NONE, DEEP, NF1),
	/* A21 : EN_FP_PWR */
	PAD_CFG_GPO(GPP_A21, 0, DEEP),
	/* A22 : EN_HDMI_PWR */
	PAD_CFG_GPO(GPP_A22, 1, DEEP),
	/* A23 : EN_SPKR_PA */
	PAD_CFG_GPO(GPP_A23, 1, DEEP),

	/* B0  : CORE_VID0 */
	PAD_CFG_NF(GPP_B0, NONE, DEEP, NF1),
	/* B1  : CORE_VID1 */
	PAD_CFG_NF(GPP_B1, NONE, DEEP, NF1),
	/* B2  : VRALERT# ==> VRALERT_L */
	PAD_CFG_NF(GPP_B2, NONE, DEEP, NF1),
	/* B3 : PEN_DET_ODL */
	PAD_CFG_GPI(GPP_B3, NONE, DEEP),
	/* B4 : WiFi_DISABLE_L */
	PAD_CFG_GPO(GPP_B4, 1, DEEP),
	/* B5 : ISH_I2C0_CVF_SDA */
	PAD_CFG_NF(GPP_B5, NONE, DEEP, NF2),
	/* B6 : ISH_I2C0_CVF_SCL */
	PAD_CFG_NF(GPP_B6, NONE, DEEP, NF2),
	/* B7 : ISH_I2C0_SENSOR_SDA */
	PAD_CFG_NF(GPP_B7, NONE, DEEP, NF2),
	/* B8 : ISH_I2C0_SENSOR_SCL */
	PAD_CFG_NF(GPP_B8, NONE, DEEP, NF2),
	/* B11 : PMCALERT# ==> PCH_WP_OD */
	PAD_CFG_GPI_GPIO_DRIVER(GPP_B11, NONE, DEEP),
	/* B12 : SLP_S0# ==> SLP_S0_L */
	PAD_CFG_NF(GPP_B12, NONE, DEEP, NF1),
	/* B13 : PLTRST# ==> PLT_RST_L */
	PAD_CFG_NF(GPP_B13, NONE, DEEP, NF1),
	/* B14 : SPKR ==> GPP_B14_STRAP */
	PAD_NC(GPP_B14, NONE),
	/* B15 : GSPI0_CS0# ==> PCH_GSPI0_H1_TPM_CS_L */
	PAD_CFG_NF(GPP_B15, NONE, DEEP, NF1),
	/* B15 : FPMCU_INT_L */
	PAD_CFG_GPI_INT(GPP_B15, NONE, PLTRST, LEVEL),
	/* B16 : PCH_I2C5_TRACKPAD_SDA */
	PAD_CFG_NF(GPP_B16, NONE, DEEP, NF2),
	/* B17 : PCH_I2C5_TRACKPAD_SCL */
	PAD_CFG_NF(GPP_B17, NONE, DEEP, NF2),
	/* B18 : EN_PP5000_TRACKPAD */
	PAD_CFG_GPO(GPP_B18, 1, DEEP),
	/* B23 : SML1ALERT# ==> GPP_B23_STRAP # */
	PAD_NC(GPP_B23, NONE),

	/* C0 : EN_PP3300_WLAN */
	PAD_CFG_GPO(GPP_C0, 1, DEEP),
	/* C1 : USI_RST_L */
	PAD_CFG_GPO(GPP_C1, 0, DEEP),
	/* C2  : SMBALERT# ==> GPP_C2_STRAP */
	PAD_NC(GPP_C2, NONE),
	/* C3 : H1_PCH_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_C3, NONE, PLTRST, LEVEL, INVERT),
	/* C4 : EN_PP5000_PEN */
	PAD_CFG_GPO(GPP_C4, 1, DEEP),
	/* C5  : SML0ALERT# ==> USB_SMB_INT_L_BOOT_STRAP0 */
	PAD_NC(GPP_C5, NONE),
	/* C6  : SML1CLK ==> EC_PCH_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_C6, NONE, PLTRST, LEVEL, INVERT),
	/* C7 : FPMCU_RST_ODL */
	PAD_CFG_GPO(GPP_C7, 1, DEEP),

	/* D0 : SSD_RTD3_EN */
	PAD_CFG_GPO(GPP_D0, 1, DEEP),
	/* D1 : ISH_ACCEL_INT_L */
	PAD_NC(GPP_D1, NONE),
	/* D2 : ISH_LID_OPEN */
	PAD_NC(GPP_D2, NONE),
	/* D3 : ISH_ALS_RGB_INT_L */
	PAD_NC(GPP_D3, NONE),
	/* D4 : FCAM_RST_L */
	PAD_CFG_GPO(GPP_D4, 0, PLTRST),
	/* D5  : SRCCLKREQ0$ ==> SSD_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D5, NONE, DEEP, NF1),
	/* D6 : WLAN_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D6, NONE, DEEP, NF1),
	/* D7  : SRCCLKREQ2# ==> NC */
	PAD_NC(GPP_D7, NONE),
	/* D8 : SD_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D8, NONE, DEEP, NF1),
	/* D9 : SD_PE_WAKE_ODL */
	PAD_CFG_GPI(GPP_D9, NONE, DEEP),
	/* D10 : EN_PP3300_WWAN */
	PAD_CFG_GPO(GPP_D10, 1, DEEP),
	/* D11 : PEN_ALERT_ODL */
	PAD_CFG_GPI(GPP_D11, NONE, DEEP),
	/* D12 : PCH_FPMCU_BOOT0 */
	PAD_CFG_GPO(GPP_D12, 0, DEEP),
	/* D13 : UART_ISH_RX_DEBUG_TX */
	PAD_CFG_NF(GPP_D13, NONE, DEEP, NF1),
	/* D14 : UART_ISH_TX_DEBUG_RX */
	PAD_CFG_NF(GPP_D14, NONE, DEEP, NF1),
	/* D15 : ISH_UART0_RTS# ==> MEM_STRAP_3 */
	PAD_NC(GPP_D15, NONE),
	/* D16 : EN_PP3300_SD */
	PAD_CFG_GPO(GPP_D16, 1, DEEP),
	/* D17 : EN_FCAM_PWR */
	PAD_CFG_GPO(GPP_D17, 0, DEEP),
	/* D18 : FCAM_SNRPWR_EN */
	PAD_CFG_GPO(GPP_D18, 0, DEEP),
	/* D19 : I2S_MCLK1 ==> I2S_MCLK1 */
	PAD_CFG_NF(GPP_D19, NONE, DEEP, NF1),

	/* E0  : SATAXPCIE0 ==> USB_A1_RT_RST_ODL */
	PAD_CFG_GPO(GPP_E0, 1, DEEP),
	/* E1 : PEN_DET_ODL */
	PAD_CFG_GPI_SCI_LOW(GPP_E1, NONE, DEEP, EDGE_SINGLE),
	/* E2 : WLAN_PCIE_WAKE_ODL */
	PAD_CFG_GPI(GPP_E2, NONE, DEEP),
	/* E3 : USI_REPORT_EN */
	PAD_CFG_GPO(GPP_E3, 0, DEEP),
	/* E4  : SATA_DEVSLP0 ==> M2_SSD_PE_WAKE_ODL */
	PAD_NC(GPP_E4, NONE),
	/* E5  : SATA_DEVSLP1 ==> M2_SSD_DEVSLP_OD */
	PAD_CFG_NF(GPP_E5, NONE, DEEP, NF1),
	/* E6  : THC0_SPI1_RST# ==> GPPE6_STRAP */
	PAD_NC(GPP_E6, NONE),
	/* E7 : USI_INT */
	PAD_CFG_GPI_APIC(GPP_E7, NONE, PLTRST, LEVEL, NONE),
	/* E8 : SLP_S0IX */
	PAD_CFG_GPO(GPP_E8, 0, DEEP),
	/* E9  : USB2_OC0# ==> USB_C1_OC_ODL */
	PAD_CFG_NF(GPP_E9, NONE, DEEP, NF1),
	/* E14 : DDPC_HPDA ==> SOC_EDP_HPD */
	PAD_CFG_NF(GPP_E14, NONE, DEEP, NF1),
	/* E15 : TRACKPAD_INT_ODL */
	PAD_CFG_GPI_IRQ_WAKE(GPP_E15, NONE, DEEP, LEVEL, INVERT),
	/* E16 : WWAN_SIM1_DET_OD */
	PAD_CFG_GPI(GPP_E16, NONE, DEEP),
	/* E17 : WWAN_PERST_L */
	PAD_CFG_GPO(GPP_E17, 1, DEEP),
	/* E18 : DDP1_CTRLCLK ==> USB_C0_LSX_SOC_TX */
	PAD_CFG_NF(GPP_E18, NONE, DEEP, NF4),
	/* E19 : DDP1_CTRLDATA ==> USB0_C0_LSX_SOC_RX_STRAP */
	PAD_CFG_NF(GPP_E19, NONE, DEEP, NF4),
	/* E20 : DDP2_CTRLCLK ==> USB_C1_LSX_SOC_TX */
	PAD_CFG_NF(GPP_E20, NONE, DEEP, NF4),
	/* E21 : DDP2_CTRLDATA ==> USB_C1_LSX_SOC_RX_STRAP */
	PAD_CFG_NF(GPP_E21, NONE, DEEP, NF4),
	/* E22 : DDPA_CTRLCLK ==> USB_C1_AUXP_DC: Retimer FW drives this pin */
	PAD_NC(GPP_E22, NONE),
	/* E23 : DDPA_CTRLDATA ==> USB_C1_AUXN_DC: Retimer FW drives this pin */
	PAD_NC(GPP_E23, NONE),

	/* F0  : CNV_BRI_DT ==> CNV_BRI_DT_STRAP */
	PAD_CFG_NF(GPP_F0, NONE, DEEP, NF1),
	/* F1  : CNV_BRI_RSP ==> NCV_BRI_RSP */
	PAD_CFG_NF(GPP_F1, UP_20K, DEEP, NF1),
	/* F2  : I2S2_TXD ==> CNV_RGI_DT_STRAP */
	PAD_CFG_NF(GPP_F2, NONE, DEEP, NF1),
	/* F3  : I2S2_RXD ==> CNV_RGI_RSP */
	PAD_CFG_NF(GPP_F3, UP_20K, DEEP, NF1),
	/* F4  : CNV_RF_RESET# ==> CNV_RF_RST_L */
	PAD_CFG_NF(GPP_F4, NONE, DEEP, NF1),
	/* F5  : MODEM_CLKREQ ==> CNV_CLKREQ0 */
	PAD_CFG_NF(GPP_F5, NONE, DEEP, NF2),
	/* F6  : WWAN_CONFIG3 */
	PAD_CFG_GPI(GPP_F6, NONE, DEEP),
	/* F7  : EN_PP3300_TRACKPAD */
	PAD_CFG_GPO(GPP_F7, 1, DEEP),
	/* F8  : I2S_MCLK2_INOUT ==> NC */
	PAD_NC(GPP_F8, NONE),
	/* F9  : HP_INT_L */
	PAD_CFG_GPI_INT(GPP_F9, NONE, PLTRST, EDGE_BOTH),
	/* F10 : EN_PP3300_TOUCHSCREEN */
	PAD_CFG_GPO(GPP_F10, 0, DEEP),
	/* F14 : WLAN_RST_ODL */
	PAD_CFG_GPO(GPP_F14, 1, DEEP),
	/* F15 : RCAM_RST_L */
	PAD_CFG_GPO(GPP_F15, 1, DEEP),
	/* F16 : PCH_GSPI1_FPMCU_CS_L */
	PAD_CFG_NF(GPP_F16, NONE, DEEP, NF4),
	/* F17 : WWAN_RF_DISABLE_ODL */
	PAD_CFG_GPO(GPP_F17, 1, DEEP),
	/* F18 : WWAN_PCIE_WAKE_ODL */
	PAD_CFG_GPI_SCI_LOW(GPP_F18, NONE, DEEP, EDGE_SINGLE),
	/* F19 : WLAN_INT_L */
	PAD_CFG_GPI_SCI_LOW(GPP_F19, NONE, DEEP, EDGE_SINGLE),
	/* F20 : WWAN_RST_ODL */
	PAD_CFG_GPO(GPP_F20, 1, DEEP),
	/* F21 : WWAN_DPR_SAR_ODL */
	PAD_CFG_GPO(GPP_F21, 1, DEEP),
	/* F22 : VNN_CTRL */
	PAD_CFG_NF(GPP_F22, NONE, DEEP, NF1),
	/* F23 : V1P05_CTRL */
	PAD_CFG_NF(GPP_F23, NONE, DEEP, NF1),

	/* H0  : GPPH0_BOOT_STRAP1 */
	PAD_NC(GPP_H0, NONE),
	/* H1  : GPPH1_BOOT_STRAP2 */
	PAD_NC(GPP_H1, NONE),
	/* H2  : GPPH2_BOOT_STRAP3 */
	PAD_NC(GPP_H2, NONE),
	/* H3 : SD_PERST_L */
	PAD_CFG_GPO(GPP_H3, 1, DEEP),
	/* H4 : PCH_I2C0_MISC_SCL */
	PAD_CFG_NF(GPP_H4, NONE, DEEP, NF1),
	/* H5 : PCH_I2C0_MISC_SDA */
	PAD_CFG_NF(GPP_H5, NONE, DEEP, NF1),
	/* H6 : PCH_I2C1_CAM_SDA */
	PAD_CFG_NF(GPP_H6, NONE, DEEP, NF1),
	/* H7 : PCH_I2C1_CAM_SCL */
	PAD_CFG_NF(GPP_H7, NONE, DEEP, NF1),
	/* H8 : WWAN_WLAN_COEX1 */
	PAD_CFG_NF(GPP_H8, NONE, DEEP, NF2),
	/* H9 : WWAN_WLAN_COEX2 */
	PAD_CFG_NF(GPP_H9, NONE, DEEP, NF2),
	/* H10 : UART_PCH_RX_DEBUG_TX */
	PAD_CFG_NF(GPP_H10, NONE, DEEP, NF2),
	/* H11 : UART_PCH_TX_DEBUG_RX */
	PAD_CFG_NF(GPP_H11, NONE, DEEP, NF2),
	/* H12 : WWAN_CONFIG0 */
	PAD_CFG_GPI(GPP_H12, NONE, DEEP),
	/* H13 : RCAM_SNRPWR_EN */
	PAD_CFG_GPO(GPP_H13, 0, DEEP),
	/* H15 : DDPB_HDMI_CTRLCLK */
	PAD_CFG_NF(GPP_H15, NONE, DEEP, NF1),
	/* H16 : DDPB_CTRLCLK ==> NC */
	PAD_NC(GPP_H16, NONE),
	/* H17 : DDPB_HDMI_CTRLDATA */
	PAD_CFG_NF(GPP_H17, NONE, DEEP, NF1),
	/* H18 : CPU_C10_GATE# ==> CPU_C10_GATE_L */
	PAD_CFG_NF(GPP_H18, NONE, DEEP, NF1),
	/* H19 : USB_C1_RT_FORCE_PWR */
	PAD_CFG_GPO(GPP_H19, 1, DEEP),
	/* H20 : EN_MIPI_RCAM_PWR */
	PAD_CFG_GPO(GPP_H20, 0, DEEP),
	/* H21 : CAM_MCLK1 */
	PAD_CFG_NF(GPP_H21, NONE, DEEP, NF1),
	/* H22 : CAM_MCLK0 */
	PAD_CFG_NF(GPP_H22, NONE, DEEP, NF1),
	/* H23 : IMGCLKOUT4 ==> NC */
	PAD_NC(GPP_H23, NONE),

	/* R0 : I2S0_HP_SCLK */
	PAD_CFG_NF(GPP_R0, NONE, DEEP, NF2),
	/* R1 : I2S0_HP_SFRM */
	PAD_CFG_NF(GPP_R1, NONE, DEEP, NF2),
	/* R2 : I2S0_PCH_TX_HP_RX_STRAP */
	PAD_CFG_NF(GPP_R2, DN_20K, DEEP, NF2),
	/* R3 : I2S0_PCH_RX_HP_TX */
	PAD_CFG_NF(GPP_R3, NONE, DEEP, NF2),
	/* R4 : DMIC_CLK0 */
	PAD_CFG_NF(GPP_R4, NONE, DEEP, NF3),
	/* R5 : DMIC_DATA0 */
	PAD_CFG_NF(GPP_R5, NONE, DEEP, NF3),
	/* R6 : WWAN_WLAN_COEX3 */
	PAD_CFG_NF(GPP_R6, NONE, DEEP, NF1),
	/* R7 : SAR0_INT_L */
	PAD_CFG_GPI_APIC(GPP_R7, NONE, PLTRST, LEVEL, NONE),


	/* S0 : I2S1_SPKR_SCLK */
	PAD_CFG_NF(GPP_S0, NONE, DEEP, NF4),
	/* S1 : I2S1_SPKR_SFRM */
	PAD_CFG_NF(GPP_S1, NONE, DEEP, NF4),
	/* S2 : I2S1_PCH_TX_SPKR_RX */
	PAD_CFG_NF(GPP_S2, NONE, DEEP, NF4),
	/* S3 : I2S1_PCH_TX_SPKR_RX */
	PAD_CFG_NF(GPP_S3, NONE, DEEP, NF4),
	/* S5 : SPKR_INT_L */
	PAD_CFG_GPI_APIC(GPP_S5, NONE, PLTRST, LEVEL, NONE),
	/* S6 : DMIC_CLK1 */
	PAD_CFG_NF(GPP_S6, NONE, DEEP, NF2),
	/* S7 : DMIC_DATA1 */
	PAD_CFG_NF(GPP_S7, NONE, DEEP, NF2),

	/* GPD0: BATLOW# ==> BATLOW_L */
	PAD_CFG_NF(GPD0, NONE, DEEP, NF1),
	/* GPD1: ACPRESENT ==> PCH_ACPRESENT */
	PAD_CFG_NF(GPD1, NONE, DEEP, NF1),
	/* GPD2: LAN_WAKE# ==> EC_PCH_WAKE_ODL */
	PAD_CFG_NF(GPD2, NONE, DEEP, NF1),
	/* GPD3: PWRBTN# ==> EC_PCH_PWR_BTN_ODL */
	PAD_CFG_NF(GPD3, NONE, DEEP, NF1),
	/* GPD4: SLP_S3# ==> SLP_S3_L */
	PAD_CFG_NF(GPD4, NONE, DEEP, NF1),
	/* GPD5: SLP_S4# ==> SLP_S4_L */
	PAD_CFG_NF(GPD5, NONE, DEEP, NF1),
	/* GPD6: SLP_A# ==> SLP_A_L */
	PAD_CFG_NF(GPD6, NONE, DEEP, NF1),
	/* GPD7: GPD7_STRAP */
	PAD_CFG_GPI(GPD7, DN_20K, DEEP),
	/* GPD8: SUSCLK ==> PCH_SUSCLK */
	PAD_CFG_NF(GPD8, NONE, DEEP, NF1),
	/* GPD9: SLP_WLAN_L */
	PAD_CFG_NF(GPD9, NONE, DEEP, NF1),
	/* GPD10: SLP_S5# ==> SLP_S5_L */
	PAD_CFG_NF(GPD10, NONE, DEEP, NF1),
	/* GPD11: LANPHYC ==> NC */
	PAD_NC(GPD11, NONE),
};

const struct pad_config *__weak variant_base_gpio_table(size_t *num)
{
	*num = ARRAY_SIZE(gpio_table);
	return gpio_table;
}

const struct pad_config *__weak variant_override_gpio_table(size_t *num)
{
	*num = 0;
	return NULL;
}

static const struct cros_gpio cros_gpios[] = {
	CROS_GPIO_REC_AL(CROS_GPIO_VIRTUAL, CROS_GPIO_DEVICE_NAME),
	CROS_GPIO_WP_AH(GPIO_PCH_WP, CROS_GPIO_DEVICE_NAME),
};

DECLARE_WEAK_CROS_GPIOS(cros_gpios);
