# Introduction

This project is used to update firmware for Goodix BerlinB/D serials touch
controller via sysfs node created by goodix_berlin driver. This source
has been compiled and tested under Linux systems with libc.

# Compile

`$make`

# How to do firmware update

**First** Confirm you have the latest upstream kernel driver for goodix_berlin driver.
With the later driver running on your device you can finde the sysfs node name `registers`
under the device sysfs path such as '/sys/bus/spi/devices/spi-GDIX9916:00/registers'.

**Then** Do firmware with this tool, following is an example for update BerlinB series touch IC.

```
fwupdate -f goodix_firmware.bin -c goodix_config.cfg -t BerlinB -d /sys/bus/spi/devices/spi-GDIX9916:00/registers
```

Note: root privilege may be needed to run this command.  
    Run `gdixfwupdate -h` to see help info.
