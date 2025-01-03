# Chronoswitch Downgrader
Chronoswitch is a downgrader for the Playstation Portable (PSP).

## Installation
Download and extract the latest version from the releases on this github page. Copy the `PSP` folder from the extracted output to your memory stick. You will need the firmware update for version you wish to downgrade to. If you want to downgrade to 6.60, you will need the 6.60 official update. If you're downgrading a PSPgo, make sure you download the official firmware appropriate for that device.

Copy the official firmware update to `PSP/GAME/UPDATE/EBOOT.PBP` on your memory stick. If you're using a PSPgo, you can use internal storage or the memory stick for the official firmware EBOOT

The downgrader is "signed", and can be launched without having a custom firmware installed. Once you run the application, follow the on-screen instructions.

## Changelog
### Version 7.6.2
* Added more user friendly firmware error output. If not running a firmware that is supported that is.
### Version 7.6.1
* Added more print statements for less common issues with parsing EBOOT.PBP or the buffer
### Version 7.6
* Changed Default color, makes it a bit easier to read.
* Detect which OFW you have to make sure your flashing the proper model OFW. ( i.e You can only flash GO OFW on GO and vice versa )
### Version 7.5
* Updated Tools to encrypt EBOOT to be OS agnostic ( from Yoti's psp_pspident )
* Bugfix: GO had issue running with just Infinity/OFW running.
### Version 7.4
* PSP GO cleanup
* Detect if EBOOT.PBP is missing from `PSP/GAME/UPDATE/`
### Version 7.3
* PSP GO can boot from ms0/ef0
### Version 7.2
* Replaced 'factory firmware limitation', which prevented certain PSPs from being downgradable at all or limited them from being downgraded to certain firmwares they theoretically support.
* This fixes most cases where an IDXFFFFFFFF or CAAFFFFFCF7 error could appear.
* Chronoswitch now detects your PSP's motherboard alongside its model and allows flashing all firmwares (5.00+) that are supported by it.
* Removed support for downgrading 09g units below 6.30.
### Version 7.1
* Added experimental support for 07g units on 6.6x.
### Version 7.0
* Added support for Infinity.
### Version 6.1
* Added support for downgrading 11g units to 6.60.
### Version 6.0
* Added support for 6.61.
### Version 5.0
* Added support for downgrading 09g units to 6.20.

## Thanks to
* some1
* bbtgp
* coyotebean
* kgsws
* Silverspring
* Bubbletune
* qwikrazor87
* The Zett

## Socials
Follow me on Twitter [@DaveeFTW](https://twitter.com/DaveeFTW), and check out [my blog](https://lolhax.org).
