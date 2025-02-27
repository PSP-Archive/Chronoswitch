/*
	Downgrade Launcher -> kernel_land.h -> Provide API documentation and definitions for the kernel operations
	by Davee
	
	28/12/2010
*/
#ifndef __KERNEL_LAND_H__
#define __KERNEL_LAND_H__

#include <psploadexec_kernel.h>
#include "include/systemctrl.h"

int getModel(void);
u32 getBaryon(void);
int launch_updater(void);
int reassign(void);
int delete_resume_game(void);

extern int (* pspKernelGetModel)(void);
extern int (* pspSysconGetBaryonVersion)(u32 *baryon);
extern SceModule2 *(* pspKernelFindModuleByName)(const char *name);
extern int (* pspKernelLoadExecVSHEf1)(const char *path, struct SceKernelLoadExecVSHParam *param);
extern int (* pspKernelLoadExecVSHMs1)(const char *path, struct SceKernelLoadExecVSHParam *param);
extern SceUID (* pspIoOpen)(char *file, int flags, SceMode mode);
extern int (* pspIoWrite)(SceUID fd, void *data, u32 len);
extern int (* pspIoClose)(SceUID fd);
extern SceUID (* pspIoRead)(int fd, void* data, int size);
extern int (* pspIoAssign)(const char *dev1, const char *dev2, const char *dev3, int mode, void *unk1, long unk2);
extern int (* pspIoUnAssign)(const char *dev);
extern int (* pspIoLseek32)(int fd, int offset, int whence);

#endif /* __KERNEL_LAND_H__ */
