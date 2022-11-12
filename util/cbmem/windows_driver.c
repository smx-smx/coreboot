/* SPDX-License-Identifier: GPL-2.0-only */

/**
 * @file windows_driver.c
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @brief chipsec driver interface
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include <fileapi.h>
#include <errhandlingapi.h>
#include <ioapiset.h>
#include <handleapi.h>
#include <sysinfoapi.h>
#include <winsvc.h>
#include <winioctl.h>
#include <synchapi.h>

#include "windows_driver.h"

#define CHIPSEC_CTL_ACCESS (FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define CLOSE_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define READ_PCI_CFG_REGISTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define WRITE_PCI_CFG_REGISTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_READ_PHYSMEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_WRITE_PHYSMEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_LOAD_UCODE_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_WRMSR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_RDMSR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_READ_IO_PORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_WRITE_IO_PORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80f, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_GET_CPU_DESCRIPTOR_TABLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_SWSMI CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_ALLOC_PHYSMEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_CPUID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_HYPERCALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_GET_PHYSADDR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_MAP_IO_SPACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_FREE_PHYSMEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_WRCR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_RDCR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_MSGBUS_SEND_MESSAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_WRITE_MMIO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
#define IOCTL_READ_MMIO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)

#define IS_VALID_HANDLE(h) ((h) != NULL && (h) != INVALID_HANDLE_VALUE)

#define DRIVER_NAME "chipsec"
#define CHIPSEC_DRIVER_ACCESS (SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE)

static char *get_windows_directory(){
	UINT size = GetWindowsDirectoryA(NULL, 0);
	char *buf = calloc(size, sizeof(char));
	GetWindowsDirectoryA(buf, size);
	return buf;
}

static HANDLE hscm = INVALID_HANDLE_VALUE;
static HANDLE hsc = INVALID_HANDLE_VALUE;
static HANDLE hfile = INVALID_HANDLE_VALUE;

static int driver_wait(DWORD desired_state){
	SERVICE_STATUS status;
	for(int i=0; i<25; i++){
		if(!QueryServiceStatus(hsc, &status)) return -1;
		if(status.dwCurrentState == desired_state) return 0;
		Sleep(200);
	}
	return -1;
}

int driver_deinit(void){
	if(IS_VALID_HANDLE(hfile)) CloseHandle(hfile);

	if(!IS_VALID_HANDLE(hsc)) return -1;

	SERVICE_STATUS status;
	QueryServiceStatus(hsc, &status);
	if(status.dwCurrentState != SERVICE_CONTROL_STOP){
		ControlService(hsc, SERVICE_CONTROL_STOP, &status);
	}
	if(driver_wait(SERVICE_STOPPED) != 0) return -1;

	if(!DeleteService(hsc)) {
		return -1;
	}
	return 0;
}


uint8_t *driver_phys_read(unsigned long long phys, size_t sz){
	uint32_t buf[3];
	buf[0] = (unsigned int)(phys >> 32);
	buf[1] = (unsigned int)(phys);
	buf[2] = (unsigned int)sz;
	uint8_t *data = calloc(sz, sizeof(uint8_t));

	DWORD bytes_returned = 0;
	if(!DeviceIoControl(hfile, IOCTL_READ_PHYSMEM,
		&buf, sizeof(buf),
		data, sz, &bytes_returned, NULL)){
			free(data);
			return NULL;
		}
	return data;
}

static HANDLE create_service(){
	char *windows_dir = get_windows_directory();
	if(windows_dir == NULL) return INVALID_HANDLE_VALUE;

	char *driver_path = NULL;
	asprintf(&driver_path, "%s\\System32\\Drivers\\chipsec_hlpr.sys", windows_dir);
	free(windows_dir);

	hsc = CreateService(hscm,
		DRIVER_NAME, "CHIPSEC Service",
		CHIPSEC_DRIVER_ACCESS,
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		driver_path,
		NULL, NULL, NULL, NULL, NULL
	);

	free(driver_path);
	return hsc;
}

int driver_init(void){
	int ret = -1;

	hscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!IS_VALID_HANDLE(hscm)){
		return ret;
	}

	do {
		hsc = OpenServiceA(hscm, DRIVER_NAME, CHIPSEC_DRIVER_ACCESS);
		if(!IS_VALID_HANDLE(hsc)){
			hsc = create_service();
			if(!IS_VALID_HANDLE(hsc)) break;
		}

		SERVICE_STATUS status;
		QueryServiceStatus(hsc, &status);
		if(status.dwCurrentState != SERVICE_RUNNING){
			if(!StartService(hsc, 0, NULL)){
				if(!DeleteService(hsc)) break;
				hsc = create_service();
				if(!StartService(hsc, 0, NULL)) break;
			}
		}

		if(driver_wait(SERVICE_RUNNING) != 0){
			break;
		}

		hfile = CreateFileA(
			"\\\\.\\\\chipsec_hlpr",
			GENERIC_ALL,
			FILE_SHARE_READ, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if(!IS_VALID_HANDLE(hfile)){
			break;
		}

		ret = 0;
	} while(0);

	CloseHandle(hscm);
	return ret;
}
