/*
    Downgrade Launcher R1
    by Davee
    
    Fin-rev 24/01/2011
*/

#include <pspkernel.h>
#include <pspsdk.h>
#include <psputility.h>
#include <pspctrl.h>

#include <pspsysmem_kernel.h>
#include <psploadexec_kernel.h>
#include <psploadcore.h>
#include <pspiofilemgr.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <malloc.h>

#include "common.h"

#include "utils.h"
#include "kernel_land.h"
#include "kernel_exploit.h"
#include "rebootex.h"

PSP_MODULE_INFO("Chronoswitch", 0, 7, 65);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_VFPU);
PSP_HEAP_SIZE_KB(3 << 10);

#define DOWNGRADER_VER    ("7.6.5")


typedef struct __attribute__((packed))
{
        int magic; // 0
        int version; // 4
        unsigned int keyofs; // 8
        unsigned int valofs; // 12
        int count; // 16
} SfoHeader;

typedef struct __attribute__((packed))
{
        unsigned short nameofs; // 0
        char alignment; // 2
        char type; // 3
        int valsize; // 4
        int totalsize; // 8
        unsigned short valofs; // 12
        short unknown; // 16
} SfoEntry;
    
u32 get_updater_version(char *argv)
{
    int i;
    char *fw_data = NULL;
    u32 pbp_header[0x28/4];
    u8 sfo_buffer[4 << 10];
    SfoHeader *header = (SfoHeader *)sfo_buffer;
    SfoEntry *entries = (SfoEntry *)((char *)sfo_buffer + sizeof(SfoHeader));
    
    /* Lets open the updater */
	SceIoStat stats;
	int status;

	status = sceIoGetstat(eboot_path, &stats);

	if(status < 0) {
		eboot_path[0] = 'm';
		eboot_path[1] = 's';
	}

	status = sceIoGetstat(eboot_path, &stats);

	int go_fw = -1;
	int size = 0;

	int go_check = sceIoOpen(eboot_path, PSP_O_RDONLY, 0);
	u8 digest[16] = { 0 };
	u8 go_buf[0x2000] = { 0 };
	SceKernelUtilsMd5Context ctx;
	sceKernelUtilsMd5BlockInit(&ctx);
	printf("Checking md5sum for EBOOT... Please wait...\n");
	while((size = sceIoRead(go_check, go_buf, sizeof(go_buf))) > 0) {
        sceKernelUtilsMd5BlockUpdate(&ctx, go_buf, size);
    }
	sceKernelUtilsMd5BlockResult(&ctx, digest);
	sceIoClose(go_check);


	u8 go_md5sum[][16] = { 
		{ 0xDB, 0x20, 0x05, 0x89, 0x52, 0xED, 0x21, 0x28, 0x74, 0x39, 0xC1, 0xC7, 0x0B, 0x56, 0x15, 0x35 },   // GO 6.10
        { 0xAE, 0x20, 0x57, 0x5E, 0xCF, 0xF8, 0x38, 0x02, 0x14, 0xE8, 0xC4, 0x3E, 0xEF, 0x46, 0x6C, 0xA8 },   // GO 6.20
        { 0x83, 0xE9, 0x3A, 0xED, 0x94, 0x83, 0xB5, 0x08, 0x72, 0x6B, 0x81, 0xC7, 0x30, 0xB5, 0x5F, 0xBB },   // GO 6.30
        { 0x2A, 0x0E, 0x2A, 0x45, 0x4E, 0x8C, 0x16, 0xCE, 0xDC, 0xEB, 0x87, 0xD2, 0x36, 0x34, 0xEC, 0xBD },   // GO 6.31
        { 0xB1, 0x47, 0x0A, 0x9C, 0x67, 0x33, 0xFA, 0x4E, 0xCD, 0x69, 0x61, 0x2A, 0xF3, 0xAF, 0xF4, 0x16 },   // GO 6.35
        { 0xD4, 0x03, 0x72, 0x6B, 0x95, 0xC3, 0x57, 0x7C, 0x33, 0x19, 0x5E, 0x49, 0x1C, 0xD8, 0xC8, 0xA1 },   // GO 6.37
        { 0xCC, 0x57, 0xA2, 0xDF, 0x91, 0x91, 0x4B, 0x0C, 0xB9, 0x86, 0xE0, 0x39, 0xC3, 0xDE, 0xFF, 0x9A },   // GO 6.38
        { 0x11, 0x6A, 0xE5, 0x36, 0x54, 0x41, 0x73, 0xDC, 0x08, 0xEE, 0x83, 0xAE, 0xB9, 0xD2, 0x26, 0xFD },   // GO 6.39
        { 0xD1, 0xFE, 0x58, 0x79, 0x8B, 0x13, 0x3E, 0xA4, 0x34, 0x3B, 0x4B, 0xB1, 0xA2, 0x5D, 0x44, 0x26 },   // GO 6.60
		{ 0xFD, 0x0F, 0x7D, 0x07, 0x98, 0xB4, 0xF6, 0xE6, 0xD3, 0x2E, 0xF9, 0x58, 0x36, 0x74, 0x05, 0x27 },   // GO 6.61
	};


	int k = 0;
	for(; k < sizeof(go_md5sum)/sizeof(go_md5sum[0]); k++) {
		if(memcmp(go_md5sum[k], digest, 16) == 0) // BAD 253
			go_fw = 1;
	}

	if(status < 0 && !strstr(argv, "ef0")) {
		printf("\nHmmmm? Are you sure you have EBOOT.PBP in PSP/GAME/UPDATE/ ???\n");
		return 0xFFF;
	}

    /* check for failure */
    int model = execKernelFunction(getModel);
	if(model == 4 && go_fw < 0) {
		pspDebugScreenSetTextColor(0xCC0000FF);
		printf("\nYou're running OFW from a X000 Series, it should be for the GO OFW\n");
    	pspDebugScreenSetTextColor(0x00BFFF);
		return 0xFFF;
	}
	else if(model != 4 && go_fw == 1) {
		pspDebugScreenSetTextColor(0xCC0000FF);
		printf("\nYou're running OFW from a GO, it should be for the X000 OFW Series\n");
    	pspDebugScreenSetTextColor(0x00BFFF);
		return 0xFFF;
	}
	else if(model == 4 && strstr(argv, "ef0") && go_fw >= 0) { return 0xFA4E; /* FAKE some reason CS on ef0 does not like reading from ms0 */ }
	SceUID fd = sceIoOpen(eboot_path, PSP_O_RDONLY, 0777);
	if (fd < 0)
	{
		printf("\nHmmmm? Are you sure you have EBOOT.PBP in PSP/GAME/UPDATE/ ???\n");
		/* error firmware */
		return 0xFFF;
	}

	/* read the PBP header */
	sceIoRead(fd, pbp_header, sizeof(pbp_header));

	/* seek to the SFO */
	sceIoLseek32(fd, pbp_header[8/4], PSP_SEEK_SET);
    
    /* calculate the size of the SFO */
    u32 sfo_size = pbp_header[12/4] - pbp_header[8/4];
    
    /* check if greater than buffer size */
    if (sfo_size > sizeof(sfo_buffer))
    {
        /* too much */
		printf("\nTo much deditated wammm ... Perhaps not have all your plugins running right now ...\n");
        sceIoClose(fd);
        return 0xFFF;
    }
	
	/* read the sfo */
	sceIoRead(fd, sfo_buffer, sizeof(sfo_buffer));

	/* close the file */
	sceIoClose(fd);
    
    /* now parse the SFO */
    for (i = 0; i < header->count; i++)
    {
        /* check this name */
        if (strcmp((char *)((char *)sfo_buffer + header->keyofs + entries[i].nameofs), "UPDATER_VER") == 0)
        {
            /* get the string */
            fw_data = (char *)((char *)sfo_buffer + header->valofs + entries[i].valofs);
            break;
        }
    }
    
    /* see if we went through all the data */
    if (i == header->count)
    {
		printf("\nHmmm SFO count is too big ... Looks like the EBOOT.PBP is corrupted somehow.\n");
        return 0xFFF;
    }
    
    /* return the firmware version */
    return (((fw_data[0] - '0') & 0xF) << 8) | (((fw_data[2] - '0') & 0xF) << 4) | (((fw_data[3] - '0') & 0xF) << 0);
}

int main(int argc, char *argv[])
{
    int res;
    SceCtrlData pad_data;
    u32 cur_buttons, prev_buttons = 0;

#ifdef HBL_SUKKIRI
    pspUtilityHtmlViewerParam html_param;
#endif
    
    /* initialise the PSP screen */
    pspDebugScreenInit();
    pspDebugScreenSetTextColor(0x00BFFF);
    //pspDebugScreenSetTextColor(0x00D05435);
    
    /* display welcome message */
    printf(
        "Chronoswitch Downgrader" "\n"
        "Version %s Built %s %s" "\n" "\n"
        
        "Contributions:" "\n"
        "\t"    "6.31/6.35 Support added by Davee" "\n"
        "\t"    "6.38/6.39/6.60 Support added by some1" "\n"
        "\t"    "6.61 Support added by qwikrazor87" "\n"
        "\t"    "Removed factory firmware limits (and more) by TheZett" "\n"
        "\t"    "GO ms0/ef0 UPDATE support added by krazynez" "\n" "\n"
        "Testers:" "\n"
        "\t"    "Peter Lustig" "\n"
        "\t"    "Nall (nallwolf)" "\n"
        "\t"    "Total Kommando" "\n" "\n"
        
        "Web:" "\n"
        "\t"    "https://lolhax.org" "\n"
        , DOWNGRADER_VER, __DATE__, __TIME__ "\n");

#ifdef HBL_SUKKIRI    
    /* Clear html param to 0 */
    memset(&html_param, 0, sizeof(pspUtilityHtmlViewerParam));
    
    /* set enough params in html viewer to get through to module loading */
    html_param.base.size = sizeof(pspUtilityHtmlViewerParam);
    html_param.base.accessThread = 0xF;
    
    /* call sceUtilityHtmlViewerInitStart to load the htmlviewer_utility.prx which imports sceutility/scepower exploit */
    res = sceUtilityHtmlViewerInitStart(&html_param);
    
    /* check error */
    if (res < 0)
    {
        /* this could be an HBL resolving issue... */
        ErrorExit(5000, "Error 0x%08X starting htmlviewer\n", res);
    }
    
    /* wait a second for htmlviewer to get loaded */
    sceKernelDelayThread(1 * 1000 * 1000);
#endif
    
    /* check firmware*/
    printf("Checking firmware... ");
    
    /* do the kernel exploit */
    doKernelExploit();
    
    /* printf ok message */
    printf("OK\n");
    
    /* set the devkit */
    g_devkit_version = sceKernelDevkitVersion();
    
    /* get the PSP model */
    int model = execKernelFunction(getModel);
    int true_model = model;
    /* get the baryon */
    u32 baryon = execKernelFunction(getBaryon);
    
    /* check for real model if it claims it is a 04g (can be 09g) */
    if (model == 3)
    {
        
        /* now get the determinating model */
        u32 det_model = (baryon >> 16) & 0xFF;
        
        /* now check if it is within range */
        if (det_model >= 0x2E && det_model < 0x30)
        {
            /* it's a 09g (or a sneaky 07g...) */
            if ((baryon >> 24) == 1)
            {
                /* 07g!! */
                true_model = 6;
            }
            else
            {
                /* 09g */
                true_model = 8;
            }
        }
    }
    
    /* display model */
    printf("Your PSP reports model %02ig.\n", model+1);
	
    
    /* check if real != true */
    if (true_model != model)
    {
        /* display */
        printf("Your PSP is originally a %02ig model.\n", true_model + 1);
        ErrorExit(10000, "Due to the experimental nature of the whole 09g to 04g downgrade, functionality to change firmware is prohibited through this program.");		
    }
	
	/* delay the thread */
    sceKernelDelayThread(1 *1000*1000);
	/* extra disclaimer for 07g devices, as support for them has been barely tested
	   theoretically they should be fully supported for fws 6.30 to 6.6x */
	if (baryon == 0x012E4000)
    {
        printf("\n" "Your PSP reports model %02ig and reflashing is slightly more risky.\n", model+1);
		printf("Proceed? (X = Yes, R = No)\n");
        while (1)
        {
            sceCtrlPeekBufferPositive(&pad_data, 1);
            
            /* filter out previous buttons */
            cur_buttons = pad_data.Buttons & ~prev_buttons;
            prev_buttons = pad_data.Buttons;
            
            /* check for cross */
            if (cur_buttons & PSP_CTRL_CROSS)
            {
                break;
            }
            
            else if (cur_buttons & PSP_CTRL_RTRIGGER)
            {
                ErrorExit(5000, "Exiting in 5 seconds.\n");
            }
        }
    }	
    
    /* delay the thread */
    sceKernelDelayThread(4*1000*1000);

    /* get the updater version */
    u32 upd_ver = get_updater_version(argv[0]);

	if (upd_ver == 0xFFF) {
		printf("\nPress R to exit...\n");
		while (1)
        {
            sceCtrlPeekBufferPositive(&pad_data, 1);
            
            /* filter out previous buttons */
            cur_buttons = pad_data.Buttons & ~prev_buttons;
            prev_buttons = pad_data.Buttons;
            
            /* check for cross */
            if (cur_buttons & PSP_CTRL_RTRIGGER)
            {
                ErrorExit(5000, "Exiting in 5 seconds.\n");
            }
        }
	}

	/* make sure that we are not attempting to downgrade a PSP below its firmware boundaries */
	
    if ((baryon == 0x00403000) && (upd_ver < 0x660)) {
        printf("This app does not support downgrading a PSP 11g below 6.60.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    } /* Disabled functionality to downgrade 09g to 6.20, otherwise would be <0x620 */
	else if ((baryon == 0x002E4000) && (upd_ver < 0x630)) {
        printf("This app does not support downgrading a PSP 09g below 6.30.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }
	else if ((baryon == 0x012E4000) && (upd_ver < 0x630)) {
        printf("This app does not support downgrading a PSP 07g below 6.30.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }	/* baryon check for TA-091, model check is done for the rare PSPgo TA-094 board (its baryon value is unknown) */
	else if (((baryon == 0x00304000) || (model == 4)) && (upd_ver < 0x570)) {
        printf("This app does not support downgrading a PSP 05g below 5.70.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }
	else if ((baryon == 0x002C4000) && (upd_ver < 0x570)) {
        printf("This app does not support downgrading a PSP 04g below 5.70.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }	
	else if (((baryon == 0x00285000) || (baryon == 0x00263100)) && (upd_ver < 0x420)) {
        printf("This app does not support downgrading a PSP 03g below 4.20.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }
	else if (((baryon == 0x00243000) || (baryon == 0x00234000) || (baryon == 0x0022B200)) && (upd_ver < 0x360)) {
        printf("This app does not support downgrading a PSP 02g below 3.60.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }
	else if (((baryon == 0x00121000) || (baryon == 0x00114000)) && (upd_ver < 0x200)) {
        printf("This app does not support downgrading a TA-082/086 PSP 01g below 2.00.\n");
        ErrorExit(5000, "Exiting in 5 seconds.\n");
    }
	
    
    /* check for 09g or 07g, we treat this as a 04g */
    if(model == 8 || model == 6)
    {
        model = 3;
    }
    
    /* check for unsupported model */
    if (model != 0 &&            /* PSP PHAT */
        model != 1 &&            /* PSP SLIM */
        model != 2 &&            /* PSP 3000 */
        model != 3 &&            /* PSP 4000/7000/9000 */
        model != 4 &&            /* PSP Go */
        model != 10              /* PSP E1000 (Street) */
    )
    {
        /* unsupported */
        ErrorExit(5000, "PSP %02ig not supported.\n", model+1);
    }
    
    /* check for pspgo */
    if (model == 4)
    {
		/* check if there is a resume game */
        if (execKernelFunction(delete_resume_game) == 0x45)
        {
			goto good;
        }

        printf("\n" "Your PSPgo will require deletion of the [Resume Game] if one is saved. Proceed? (X = Yes, R = No)\n");
        
        while (1)
        {
            sceCtrlPeekBufferPositive(&pad_data, 1);
            
            /* filter out previous buttons */
            cur_buttons = pad_data.Buttons & ~prev_buttons;
            prev_buttons = pad_data.Buttons;
            
            /* check for cross */
            if (cur_buttons & PSP_CTRL_CROSS)
            {
                break;
            }
            
            else if (cur_buttons & PSP_CTRL_RTRIGGER)
            {
                ErrorExit(5000, "Exiting in 5 seconds.\n");
            }
        }
        
        /* delete resume game */
        if (execKernelFunction(delete_resume_game) < 0)
        {
            /* ERROR */
            ErrorExit(5000, "Error deleting [Resume Game]. Exiting for safety reasons.\n");
        }
    }
good:;
    
    int isInfinity = !(infGetVersion() & 0x80000000);
    
    if (isInfinity)
    {
        printf("\n" "Your PSP is running Infinity and reflashing is slightly more risky. Proceed? (X = Yes, R = No)\n");
        
        while (1)
        {
            sceCtrlPeekBufferPositive(&pad_data, 1);
            
            /* filter out previous buttons */
            cur_buttons = pad_data.Buttons & ~prev_buttons;
            prev_buttons = pad_data.Buttons;
            
            /* check for cross */
            if (cur_buttons & PSP_CTRL_CROSS)
            {
                break;
            }
            
            else if (cur_buttons & PSP_CTRL_RTRIGGER)
            {
                ErrorExit(5000, "Exiting in 5 seconds.\n");
            }
        }
    }
    
    /* do confirmation stuff */
	if(model == 4 && strstr(argv[0], "ef0")) {
    	printf("\nEBOOT.PBP is correct press X to continue, R to exit.\n");
	}
	else {
    	printf("\n" "Currently Running: %X.%X going to Downgrade/Reinstall: %X.%X.\n", (g_devkit_version >> 24) & 0xF, ((g_devkit_version >> 12) & 0xF0) | ((g_devkit_version >> 8) & 0xF), (upd_ver >> 8) & 0xF, upd_ver & 0xFF);
    	printf("\nX to continue, R to exit.\n");
	}
    
    /* get button */
    while (1)
    {
        sceCtrlPeekBufferPositive(&pad_data, 1);

        /* filter out previous buttons */
        cur_buttons = pad_data.Buttons & ~prev_buttons;
        prev_buttons = pad_data.Buttons;

        
        /* check for cross */
        if (cur_buttons & PSP_CTRL_CROSS)
        {
            break;
        }
        
        else if (cur_buttons & PSP_CTRL_RTRIGGER)
        {
            ErrorExit(5000, "Exiting in 5 seconds.\n");
        }
    }
    
    /* clear screen */
    pspDebugScreenClear();
    
    /* update should be OK, go for it */
    printf("By running this application and launching the SCE updater you accept all responsibility of any damage, temporary or permament, that may occur when using this application. This application has been tested with no loss of functionality or any damage to the system, however  it cannot be guaranteed to be completely safe." "\n" "BY RUNNING THIS APPLICATION YOU ACCEPT ALL THE RISK INVOLVED.\n\n" "Press X to start SCE updater. Press R to exit\n");
    
    while (1)
    {
        sceCtrlPeekBufferPositive(&pad_data, 1);

        /* filter out previous buttons */
        cur_buttons = pad_data.Buttons & ~prev_buttons;
        prev_buttons = pad_data.Buttons;
        
        /* check for cross */
        if (cur_buttons & PSP_CTRL_CROSS)
        {
            break;
        }
        
        else if (cur_buttons & PSP_CTRL_RTRIGGER)
        {
            ErrorExit(5000, "Exiting in 5 seconds.\n");
        }
    }

    printf("OK, good for launch!\n");
    
    /* go go go go go */
    res = execKernelFunction(launch_updater);
    
    printf("loading SCE updater failed = 0x%08X\n", res);
    sceKernelDelayThread(5 *1000*1000);
    sceKernelExitGame();
    return 0;
}
