## SPDX-License-Identifier: GPL-2.0-only

ifneq ($(filter y,$(CONFIG_VENDORCODE_ELTAN_VBOOT) $(CONFIG_VENDORCODE_ELTAN_MBOOT)),)

CPPFLAGS_common += -I$(src)/security/vboot

bootblock-y += ../../../../security/vboot/vboot_lib.c
bootblock-y += vboot_check.c
postcar-y += vboot_check.c
romstage-y += vboot_check.c
ramstage-y += vboot_check.c

$(call src-to-obj,bootblock,$(dir)/vboot_check.c) : $(obj)/fmap_config.h
$(call src-to-obj,postcar,$(dir)/vboot_check.c) : $(obj)/fmap_config.h
$(call src-to-obj,romstage,$(dir)/vboot_check.c) : $(obj)/fmap_config.h
$(call src-to-obj,ramstage,$(dir)/vboot_check.c) : $(obj)/fmap_config.h

ifeq ($(CONFIG_VENDORCODE_ELTAN_VBOOT),y)
cbfs-files-y += oemmanifest.bin
oemmanifest.bin-file     := $(obj)/oemmanifest.bin
oemmanifest.bin-position := $(CONFIG_VENDORCODE_ELTAN_OEM_MANIFEST_LOC)
oemmanifest.bin-type     := raw

$(obj)/oemmanifest.bin:
ifeq ($(CONFIG_VENDORCODE_ELTAN_VBOOT_SIGNED_MANIFEST),y)
	dd if=/dev/zero of=$@ seek=8 bs=$(CONFIG_VENDORCODE_ELTAN_OEM_MANIFEST_ITEM_SIZE) count=$(CONFIG_VENDORCODE_ELTAN_OEM_MANIFEST_ITEMS)
else # ($(CONFIG_VERIFIED_BOOT_SIGNED_MANIFEST),y)
	dd if=/dev/zero of=$@ bs=$(CONFIG_VENDORCODE_ELTAN_OEM_MANIFEST_ITEM_SIZE) count=$(CONFIG_VENDORCODE_ELTAN_OEM_MANIFEST_ITEMS)
endif # ($(CONFIG_VENDORCODE_ELTAN_VBOOT_SIGNED_MANIFEST),y)

ifeq ($(CONFIG_VENDORCODE_ELTAN_VBOOT_SIGNED_MANIFEST),y)
cbfs-files-y += vboot_public_key.bin
vboot_public_key.bin-file     := $(call strip_quotes, $(CONFIG_VENDORCODE_ELTAN_VBOOT_KEY_FILE))
vboot_public_key.bin-position := $(CONFIG_VENDORCODE_ELTAN_VBOOT_KEY_LOCATION)
vboot_public_key.bin-type     := raw

endif # ($(CONFIG_VENDORCODE_ELTAN_VBOOT_SIGNED_MANIFEST),y)
endif # CONFIG_VENDORCODE_ELTAN_VBOOT

endif # CONFIG_VENDORCODE_ELTAN_VBOOT or CONFIG_VENDORCODE_ELTAN_MBOOT
