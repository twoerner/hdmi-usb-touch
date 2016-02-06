/*
 * Copyright (C) 2016  Trevor Woerner <twoerner@gmail.com>
 * LICENSE: MIT (see COPYING.MIT file)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
#include <libudev.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/uinput.h>
#include <linux/input.h>

#include "config.h"

#define MAX_TOUCH 5
#define LOG(__level,__fmt, ...) do_log(__level, __FILE__, __LINE__, __fmt, ##__VA_ARGS__)

typedef struct __attribute__((packed)) {
	uint8_t startByte;
	uint8_t anyTouch;
	uint16_t touchX1;
	uint16_t touchY1;
	uint8_t multiStart;
	uint8_t touchBitmask;
	uint16_t touchX2;
	uint16_t touchY2;
	uint16_t touchX3;
	uint16_t touchY3;
	uint16_t touchX4;
	uint16_t touchY4;
	uint16_t touchX5;
	uint16_t touchY5;
	uint8_t endByte;
} RawTouchEventMsg_t;

typedef struct {
	uint16_t x;
	uint16_t y;
} Coord_t;

typedef struct {
	uint8_t anyTouch;
	bool touchBitmask[MAX_TOUCH];
	Coord_t touches[MAX_TOUCH];
} TouchMsg_t;

// forward refs
static void version(void);
static void usage(const char *cmd_p);
static int process_cmdline_args(int argc, char *argv[]);
static int find_input_touch_device(char *inputDeviceStrOut_p);
static void setup_signal_handler(void);
static bool valid(RawTouchEventMsg_t msg);
static bool duplicate(TouchMsg_t thisMsg);
TouchMsg_t format_touch_msg(RawTouchEventMsg_t rawMsg);

static int configure_uinput_device(void);
static void send_event(int fd, TouchMsg_t msg);

static void log_raw_touch_event(RawTouchEventMsg_t msg);
static void log_xy_event(TouchMsg_t msg);
__attribute__((format (printf, 4, 5))) void do_log(unsigned level, const char *filename_p, unsigned lineno, const char *fmt_p, ...);

// globals
char *class_pG = NULL;
char *classDefault_pG = "hidraw";
unsigned vendorID_G = 0xeef;
unsigned productID_G = 0x0005;
bool daemonize_G = true;
unsigned verbose_G = 0;
int32_t maxX_G = 800;
int32_t maxY_G = 480;
jmp_buf env_G;

int
main (int argc, char *argv[])
{
	int retInt = 0;
	ssize_t retRead;
	char inputDeviceStr_p[PATH_MAX];
	volatile int inFd = -1, outFd = -1;
	RawTouchEventMsg_t rawTouchMsg;
	TouchMsg_t touchMsg;

	// handle signals
	if (setjmp(env_G) != 0) {
		LOG(3, "cleanup (jmp)\n");
		if (outFd > 0) {
			ioctl(outFd, UI_DEV_DESTROY);
			close(outFd);
		}
		if (inFd > 0)
			close(inFd);
		if (class_pG != NULL)
			free(class_pG);
		return 0;
	}
	setup_signal_handler();

	// cmdline args
	retInt = process_cmdline_args(argc, argv);
	if (retInt != 0)
		return 1;

	// daemon
	if (daemonize_G) {
		retInt = daemon(1, 0);
		if (retInt != 0) {
			LOG(2, "damon()");
			retInt = 1;
			goto cleanup;
		}
	}

	while (1) {
		// look for the input device associated with vendorID:productID
		memset(inputDeviceStr_p, 0, sizeof(inputDeviceStr_p));
		retInt = find_input_touch_device(inputDeviceStr_p);
		if (retInt != 0) {
			LOG(3, "can't find input touch device vendor:0x%04x product:0x%04x (is it connected?)\n", vendorID_G, productID_G);
			goto cleanup;
		}
		LOG(2, "input device: %s\n", inputDeviceStr_p);

		// open input file
		inFd = open(inputDeviceStr_p, O_RDONLY);
		if (inFd < 0) {
			LOG(3, "open(inFd)");
			retInt = -1;
			goto cleanup;
		}

		// open and configure output file
		outFd = configure_uinput_device();
		if (retInt < 0) {
			LOG(3, "unable to configure uinput\n");
			retInt = -1;
			goto cleanup1;
		}

		// process events
		while (1) {
			retRead = read(inFd, &rawTouchMsg, sizeof(rawTouchMsg));
			if (retRead < 0)
				break;
			if (retRead != sizeof(rawTouchMsg)) {
				LOG(3, "only received %zd out of %ld expected\n", retRead, sizeof(rawTouchMsg));
				continue;
			}
			log_raw_touch_event(rawTouchMsg);
			if (!valid(rawTouchMsg))
				continue;
			touchMsg = format_touch_msg(rawTouchMsg);
			if (duplicate(touchMsg)){
				/*continue*/;}
			log_xy_event(touchMsg);
			send_event(outFd, touchMsg);
		}

		ioctl(outFd, UI_DEV_DESTROY);
		close(outFd);
		close(inFd);
	}

	retInt = 0;

	ioctl(outFd, UI_DEV_DESTROY);
	close(outFd);
cleanup1:
	close(inFd);
cleanup:
	if (class_pG != NULL)
		free(class_pG);
	return retInt;
}

static void
send_uinput_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct input_event outEvent;
	char logMsg[256];
	char *ptr;

	memset(logMsg, 0, sizeof(logMsg));
	ptr = logMsg;

	snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "type:");
	ptr = logMsg + strlen(logMsg);
	switch(type) {
		case EV_ABS:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "EV_ABS ");
			ptr = logMsg + strlen(logMsg);
			break;

		case EV_SYN:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "EV_SYN ");
			ptr = logMsg + strlen(logMsg);
			break;

		default:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "?(%u) ", type);
			ptr = logMsg + strlen(logMsg);
			break;
	}

	snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, " code:");
	ptr = logMsg + strlen(logMsg);
	switch(code) {
		case ABS_MT_SLOT:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "%-20s", "ABS_MT_SLOT ");
			ptr = logMsg + strlen(logMsg);
			break;

		case ABS_MT_TRACKING_ID:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "%-20s", "ABS_MT_TRACKING_ID ");
			ptr = logMsg + strlen(logMsg);
			break;

		case ABS_MT_POSITION_X:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "%-20s", "ABS_MT_POSITION_X ");
			ptr = logMsg + strlen(logMsg);
			break;

		case ABS_MT_POSITION_Y:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "%-20s", "ABS_MT_POSITION_Y ");
			ptr = logMsg + strlen(logMsg);
			break;

		case SYN_MT_REPORT:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "%-20s", "SYN_MT_REPORT ");
			ptr = logMsg + strlen(logMsg);
			break;

		case SYN_REPORT:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "%-20s", "SYN_REPORT ");
			ptr = logMsg + strlen(logMsg);
			break;

		default:
			snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, "?(%u) ", code);
			ptr = logMsg + strlen(logMsg);
			break;
	}

	snprintf(ptr, sizeof(logMsg) - strlen(logMsg) - 1, " value:%d", value);

	LOG(2, "=> uinput event: %s\n", logMsg);

	memset(&outEvent, 0, sizeof(outEvent));
	outEvent.type = type;
	outEvent.code = code;
	outEvent.value = value;
	write(fd, &outEvent, sizeof(outEvent));
}

static void
send_event(int fd, TouchMsg_t msg)
{
	int i;
	bool someReport = false;
	static bool lastMask[MAX_TOUCH] = {false, false, false, false, false};

	for (i=0; i<MAX_TOUCH; ++i) {
		if (lastMask[i] && !msg.touchBitmask[i]) {
			someReport = true;
			send_uinput_event(fd, EV_ABS, ABS_MT_SLOT, i);
			send_uinput_event(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
			send_uinput_event(fd, EV_SYN, SYN_MT_REPORT, 0);
		}
	}

	for (i=0; i<MAX_TOUCH; ++i) {
		if (msg.touchBitmask[i]) {
			if ((msg.touches[i].x == 0) && (msg.touches[i].y == 0))
				continue;
			lastMask[i] = true;
			someReport = true;
			send_uinput_event(fd, EV_ABS, ABS_MT_SLOT, i);
			send_uinput_event(fd, EV_ABS, ABS_MT_TRACKING_ID, i);
			send_uinput_event(fd, EV_ABS, ABS_MT_POSITION_X, msg.touches[i].x);
			send_uinput_event(fd, EV_ABS, ABS_MT_POSITION_Y, msg.touches[i].y);
			send_uinput_event(fd, EV_SYN, SYN_MT_REPORT, 0);
		}
		else
			lastMask[i] = false;
	}

	if (!someReport)
		send_uinput_event(fd, EV_SYN, SYN_MT_REPORT, 0);

	LOG(2, "\n");
}

static int
configure_uinput_device(void)
{
	int uinputFd, ret;
	ssize_t retWrite;
	struct uinput_user_dev uinputDev;
	struct {
		unsigned int cmd;
		unsigned long arg;
	} ioctlConfigCmds[] = {
		{UI_SET_EVBIT, EV_KEY},
		{UI_SET_EVBIT, EV_SYN},
		{UI_SET_EVBIT, EV_ABS},
		{UI_SET_ABSBIT, ABS_X},
		{UI_SET_ABSBIT, ABS_Y},
		{UI_SET_ABSBIT, ABS_MT_SLOT},
		{UI_SET_ABSBIT, ABS_MT_TRACKING_ID},
		{UI_SET_ABSBIT, ABS_MT_POSITION_X},
		{UI_SET_ABSBIT, ABS_MT_POSITION_Y},
		{UI_SET_KEYBIT, BTN_TOUCH},
	};
	int i, ioctlConfigCmdsCnt = sizeof(ioctlConfigCmds) / sizeof(ioctlConfigCmds[0]);

	uinputFd = open("/dev/input/uinput", O_WRONLY | O_NONBLOCK);
	if (uinputFd < 0) {
		uinputFd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
		if (uinputFd < 0) {
			LOG(2, "open(uinputFd)");
			return -1;
		}
	}

	memset(&uinputDev, 0, sizeof(uinputDev));
	snprintf(uinputDev.name, UINPUT_MAX_NAME_SIZE, "HDMI-USB-touch");
	uinputDev.id.bustype = BUS_VIRTUAL;
	uinputDev.id.vendor = 0xeef;
	uinputDev.id.product = 5;
	uinputDev.id.version = 1;
	uinputDev.absmax[ABS_X] = maxX_G;
	uinputDev.absmax[ABS_Y] = maxY_G;
	uinputDev.absmax[ABS_MT_POSITION_X] = maxX_G;
	uinputDev.absmax[ABS_MT_POSITION_Y] = maxY_G;
	uinputDev.absmax[ABS_MT_SLOT] = MAX_TOUCH;
	uinputDev.absmax[ABS_MT_TRACKING_ID] = MAX_TOUCH;
	retWrite = write(uinputFd, &uinputDev, sizeof(uinputDev));
	if (retWrite == -1) {
		LOG(2, "write(uinputFd)");
		close(uinputFd);
		return -1;
	}

	for (i=0; i<ioctlConfigCmdsCnt; ++i) {
		ret = ioctl(uinputFd, ioctlConfigCmds[i].cmd, ioctlConfigCmds[i].arg);
		if (ret != 0) {
			LOG(2, "ioctl()");
			close(uinputFd);
			return -1;
		}
	}

	ret = ioctl(uinputFd, UI_DEV_CREATE);
	if (ret != 0) {
		LOG(2, "ioctl(UI_DEV_CREATE)");
		close(uinputFd);
		return -1;
	}

	return uinputFd;
}

static bool
valid(RawTouchEventMsg_t msg)
{
	if (msg.startByte != 0xaa) {
		LOG(3, "  => (unexpected start byte: 0x%02x (exp:0xaa))\n", msg.startByte);
		return false;
	}
	if (msg.multiStart != 0xbb) {
		LOG(3, "  => (unexpected multi-start byte: 0x%02x (exp:0xbb))\n", msg.multiStart);
		return false;
	}
	if ((msg.endByte != 0xcc) && (msg.endByte != 0)) {
		LOG(3, "  => (unexpected end byte: 0x%02x (exp:0xcc|0x00))\n", msg.endByte);
		return false;
	}

	return true;
}

static bool
duplicate(TouchMsg_t thisMsg)
{
	static bool firstTime = true;
	static TouchMsg_t lastMsg;
	bool dup = false;
	int i;

	if (firstTime) {
		firstTime = false;
		goto dupRet;
	}

	for (i=0; i<MAX_TOUCH; ++i) {
		if (thisMsg.touchBitmask[i] != lastMsg.touchBitmask[i])
			goto dupRet;
	}

	for (i=0; i<MAX_TOUCH; ++i) {
		if (thisMsg.touchBitmask[i]) {
			if (thisMsg.touches[i].x != lastMsg.touches[i].x)
				goto dupRet;
			if (thisMsg.touches[i].y != lastMsg.touches[i].y)
				goto dupRet;
		}
	}

	LOG(2, "  => (duplicate)\n");
	dup = true;

dupRet:
	lastMsg = thisMsg;
	return dup;
}

TouchMsg_t
format_touch_msg(RawTouchEventMsg_t rawMsg)
{
	TouchMsg_t outMsg;

	memset(&outMsg, 0, sizeof(outMsg));

	outMsg.anyTouch = rawMsg.anyTouch;

	if (rawMsg.touchBitmask & (1<<0))
		outMsg.touchBitmask[0] = true;
	if (rawMsg.touchBitmask & (1<<1))
		outMsg.touchBitmask[1] = true;
	if (rawMsg.touchBitmask & (1<<2))
		outMsg.touchBitmask[2] = true;
	if (rawMsg.touchBitmask & (1<<3))
		outMsg.touchBitmask[3] = true;
	if (rawMsg.touchBitmask & (1<<4))
		outMsg.touchBitmask[4] = true;

	outMsg.touches[0].x = (uint16_t)(((rawMsg.touchX1 & 0x00ff) << 8) | ((rawMsg.touchX1 & 0xff00) >> 8));
	outMsg.touches[0].y = (uint16_t)(((rawMsg.touchY1 & 0x00ff) << 8) | ((rawMsg.touchY1 & 0xff00) >> 8));

	outMsg.touches[1].x = (uint16_t)(((rawMsg.touchX2 & 0x00ff) << 8) | ((rawMsg.touchX2 & 0xff00) >> 8));
	outMsg.touches[1].y = (uint16_t)(((rawMsg.touchY2 & 0x00ff) << 8) | ((rawMsg.touchY2 & 0xff00) >> 8));

	outMsg.touches[2].x = (uint16_t)(((rawMsg.touchX3 & 0x00ff) << 8) | ((rawMsg.touchX3 & 0xff00) >> 8));
	outMsg.touches[2].y = (uint16_t)(((rawMsg.touchY3 & 0x00ff) << 8) | ((rawMsg.touchY3 & 0xff00) >> 8));

	outMsg.touches[3].x = (uint16_t)(((rawMsg.touchX4 & 0x00ff) << 8) | ((rawMsg.touchX4 & 0xff00) >> 8));
	outMsg.touches[3].y = (uint16_t)(((rawMsg.touchY4 & 0x00ff) << 8) | ((rawMsg.touchY4 & 0xff00) >> 8));

	outMsg.touches[4].x = (uint16_t)(((rawMsg.touchX5 & 0x00ff) << 8) | ((rawMsg.touchX5 & 0xff00) >> 8));
	outMsg.touches[4].y = (uint16_t)(((rawMsg.touchY5 & 0x00ff) << 8) | ((rawMsg.touchY5 & 0xff00) >> 8));

	return outMsg;
}

static int
find_input_touch_device(char *inputDeviceStrOut_p)
{
	int retInt = 0, iteration = 0;
	struct udev *inputUDevice_p, *monitorUDevice_p;
	struct udev_enumerate *udevEnumerate_p;
	struct udev_list_entry *udevAllDevices_p, *udevOneDevice_p;
	char wantVendorID[5], wantProductID[5];
	const char *foundVendorID_p, *foundProductID_p;
	const char *foundDevNode_p;
	int vendorCmp, productCmp;
	bool found = false;
	struct udev_monitor *udevMonitor_p;
	struct udev_device *device_p, *parent_p;
	int monitorFd;

	if (inputDeviceStrOut_p == NULL) {
		LOG(3, "NULL output pointer\n");
		return -1;
	}

	*inputDeviceStrOut_p = 0;

	retInt = snprintf(wantVendorID, sizeof(wantVendorID), "%04x", vendorID_G);
	if (retInt != 4) {
		LOG(3, "snprintf()");
		return retInt;
	}

	retInt = snprintf(wantProductID, sizeof(wantProductID), "%04x", productID_G);
	if (retInt != 4) {
		LOG(3, "snprintf()");
		return retInt;
	}

	// setup monitoring
	monitorUDevice_p = udev_new();
	if (monitorUDevice_p == NULL) {
		LOG(3, "udev_new(monitor)");
		return -1;
	}
	udevMonitor_p = udev_monitor_new_from_netlink(monitorUDevice_p, "udev");
	if (udevMonitor_p == NULL) {
		LOG(3, "udev_monitor_new_from_netlink()");
		return -1;
	}
	if (class_pG == NULL)
		retInt = udev_monitor_filter_add_match_subsystem_devtype(udevMonitor_p, classDefault_pG, NULL);
	else
		retInt = udev_monitor_filter_add_match_subsystem_devtype(udevMonitor_p, class_pG, NULL);
	if (retInt != 0) {
		LOG(3, "udev_monitor_filter_add_match_subsystem_devtype()");
		return retInt;
	}
	retInt = udev_monitor_enable_receiving(udevMonitor_p);
	if (retInt != 0) {
		LOG(3, "udev_monitor_enable_receiving()");
		return retInt;
	}
	monitorFd = udev_monitor_get_fd(udevMonitor_p);
	if (monitorFd < 0) {
		LOG(3, "udev_monitor_get_fd()");
		return -1;
	}


	// look for our vendor:device
	do {
		iteration = 0;

		inputUDevice_p = udev_new();
		if (monitorUDevice_p == NULL) {
			LOG(3, "udev_new(input)");
			return -1;
		}

		udevEnumerate_p = udev_enumerate_new(inputUDevice_p);
		if (udevEnumerate_p == NULL) {
			LOG(2, "udev_enumerate_new():");
			return errno;
		}

		if (class_pG == NULL) {
			LOG(2, "class: %s\n", classDefault_pG);
			retInt = udev_enumerate_add_match_subsystem(udevEnumerate_p, classDefault_pG);
		}
		else {
			LOG(2, "class: %s\n", class_pG);
			retInt = udev_enumerate_add_match_subsystem(udevEnumerate_p, class_pG);
		}
		if (retInt != 0) {
			LOG(3, "udev_enumerate_add_match_subsystem():");
			return retInt;
		}

		retInt = udev_enumerate_scan_devices(udevEnumerate_p);
		if (retInt != 0) {
			LOG(3, "udev_enumerate_scan_devices():");
			return retInt;
		}

		udevAllDevices_p = udev_enumerate_get_list_entry(udevEnumerate_p);
		udev_list_entry_foreach(udevOneDevice_p, udevAllDevices_p) {
			const char *path_p;

			++iteration;

			path_p = udev_list_entry_get_name(udevOneDevice_p);
			device_p = udev_device_new_from_syspath(inputUDevice_p, path_p);
			if (device_p == NULL)
				continue;

			foundDevNode_p = udev_device_get_devnode(device_p);
			LOG(2, "%d\n", iteration);
			LOG(2, "\tdevice: %s\n", udev_device_get_sysname(device_p));
			LOG(2, "\tdevice path: %s\n", path_p);
			LOG(2, "\tdevice node: %s\n", foundDevNode_p);

			parent_p = udev_device_get_parent_with_subsystem_devtype(device_p, "usb", "usb_device");
			if (parent_p == NULL) {
				udev_device_unref(device_p);
				continue;
			}
			foundVendorID_p = udev_device_get_sysattr_value(parent_p, "idVendor");
			foundProductID_p = udev_device_get_sysattr_value(parent_p, "idProduct");
			LOG(2, "\tparent: %s\n", udev_device_get_sysname(parent_p));
			LOG(2, "\tidVendor:%s idProduct:%s manufacturer:%s product:%s serial:%s\n",
					foundVendorID_p, foundProductID_p,
					udev_device_get_sysattr_value(parent_p, "manufacturer"),
					udev_device_get_sysattr_value(parent_p, "product"),
					udev_device_get_sysattr_value(parent_p, "serial"));

			vendorCmp = strncmp(wantVendorID, foundVendorID_p, strlen(wantVendorID));
			productCmp = strncmp(wantProductID, foundProductID_p, strlen(wantProductID));

			if ((vendorCmp == 0) && (productCmp == 0)) {
				found = true;
				snprintf(inputDeviceStrOut_p, PATH_MAX, foundDevNode_p);
			}

			udev_device_unref(device_p);
		}

		if (iteration == 0)
			LOG(2, "-- no devices --\n");

		udev_enumerate_unref(udevEnumerate_p);
		udev_unref(inputUDevice_p);

		if (!found) {
			fd_set fds;

			FD_ZERO(&fds);
			FD_SET(monitorFd, &fds);
			retInt = select(monitorFd+1, &fds, NULL, NULL, NULL);
			if ((retInt > 0) && FD_ISSET(monitorFd, &fds)) {
				device_p = udev_monitor_receive_device(udevMonitor_p);
				fprintf(stderr, "  ==> monitor action: %s\n", udev_device_get_action(device_p));
				udev_device_unref(device_p);
			}
		}
	} while (!found);

	udev_monitor_unref(udevMonitor_p);
	udev_unref(monitorUDevice_p);
	return found? 0 : 1;
}

static void
version(void)
{
	printf("%s\n", PACKAGE_STRING);
}

static void
usage(const char *cmd_p)
{
	version();
	printf("\nUsage: ");
	if (cmd_p != NULL)
		printf("%s [options]", cmd_p);
	printf("\n  options:\n");
	printf("    -h|--help                Print this help and exit successfully.\n");
	printf("    -V|--version             Print version and exit successfully.\n");
	printf("    -v|--verbose             Add verbosity (each instance adds verbosity).\n");
	printf("    --class <subsystem>      Use <class> instead of default \"%s\".\n", classDefault_pG);
	printf("    --vendor <vendorID>      Use <vendorID> instead of default: \"0x%04x\".\n", vendorID_G);
	printf("    --product <productID>    Use <productID> instead of default: \"0x%04x\".\n", productID_G);
	printf("    --no-daemon              Do not daemonize app (implies --verbose).\n");
	printf("    -x|--max-x <int32>       Maximum X resolution (default: %d).\n", maxX_G);
	printf("    -y|--max-y <int32>       Maximum Y resolution (default: %d).\n", maxY_G);
	printf("\n");
}

static int
process_cmdline_args (int argc, char *argv[])
{
	int c, retInt = 0;
	unsigned tmpUInt;
	int32_t tmpInt;
	struct option longOpts[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'V'},
		{"verbose", no_argument, NULL, 'v'},
		{"class", required_argument, NULL, 0},
		{"vendor", required_argument, NULL, 1},
		{"product", required_argument, NULL, 2},
		{"no-daemon", no_argument, NULL, 3},
		{"max-x", required_argument, NULL, 'x'},
		{"max-y", required_argument, NULL, 'y'},
		{NULL, 0, NULL, 0},
	};

	for (;;) {
		c = getopt_long(argc, argv, "hc:Vvx:y:", longOpts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);

			case 'V':
				version();
				exit(0);

			case 'v':
				++verbose_G;
				break;

			case 0:
				class_pG = strdup(optarg);
				break;

			case 1:
				if (sscanf(optarg, "%u", &tmpUInt) != 1) {
					LOG(2, "sscanf()");
					usage(argv[0]);
					exit(1);
				}
				vendorID_G = tmpUInt;
				break;

			case 2:
				if (sscanf(optarg, "%u", &tmpUInt) != 1) {
					LOG(2, "sscanf():");
					usage(argv[0]);
					exit(1);
				}
				productID_G = tmpUInt;
				break;

			case 3:
				daemonize_G = false;
				++verbose_G;
				break;

			case 'x':
				if (sscanf(optarg, "%d", &tmpInt) != 1) {
					LOG(2, "sscanf()");
					usage(argv[0]);
					exit(1);
				}
				maxX_G = tmpInt;
				break;

			case 'y':
				if (sscanf(optarg, "%d", &tmpInt) != 1) {
					LOG(2, "sscanf()");
					usage(argv[0]);
					exit(1);
				}
				maxY_G = tmpInt;
				break;

			default:
				fprintf (stderr, "unhandled cmdline arg: %c (0x%02x)\n", optopt, optopt);
				retInt = 1;
				break;
		}
	}

	return retInt;
}

/* -- signal handling -- */
static void
signal_handler (int signo, __attribute__((unused)) siginfo_t *info_p, __attribute__((unused)) void *ctx_p)
{
	longjmp(env_G, signo);
}

static void
setup_signal_handler(void)
{
	struct sigaction sig;

	sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_SIGINFO;
	sig.sa_sigaction = signal_handler;
	sigaction(SIGINT, &sig, NULL);
	sigaction(SIGQUIT, &sig, NULL);
}

/* -- logging -- */
static void
log_raw_touch_event(RawTouchEventMsg_t rawTouchMsg)
{
	unsigned i;
	union {
		RawTouchEventMsg_t msg;
		uint8_t data[sizeof(RawTouchEventMsg_t)];
	} dataUnion;
	char rawDataStr[(sizeof(RawTouchEventMsg_t) * 3) + 10];
	char *ptr;

	LOG(3, "message:\n");

	dataUnion.msg = rawTouchMsg;
	ptr = rawDataStr;
	memset(rawDataStr, 0, sizeof(rawDataStr));
	for (i=0; i<sizeof(rawTouchMsg); ++i) {
		snprintf(ptr, sizeof(rawDataStr) - strlen(rawDataStr) - 1, "%02x ", dataUnion.data[i]);
		ptr = rawDataStr + strlen(rawDataStr);
	}
	LOG(2, "%s\n", rawDataStr);

	LOG(3, "%10s: 0x%02x\n", "start", rawTouchMsg.startByte);
	LOG(3, "%10s: 0x%02x\n", "multi", rawTouchMsg.multiStart);
	LOG(3, "%10s: 0x%02x\n", "end", rawTouchMsg.endByte);
	LOG(3, "%10s: %d\n", "anytouch", rawTouchMsg.anyTouch? 1 : 0);

	ptr = rawDataStr;
	memset(rawDataStr, 0, sizeof(rawDataStr));
	snprintf(ptr, sizeof(rawDataStr) - 1, "%10s: ", "bitmsk");
	ptr = rawDataStr + strlen(rawDataStr);
	for (i=8; i>0; --i) {
		if (rawTouchMsg.touchBitmask & (1<<(i-1)))
			snprintf(ptr, sizeof(rawDataStr) - strlen(rawDataStr) - 1, "%d", i);
		else
			snprintf(ptr, sizeof(rawDataStr) - strlen(rawDataStr) - 1, "-");
		ptr = rawDataStr + strlen(rawDataStr);
	}
	LOG(3, "%s\n", rawDataStr);
}

static void
log_xy_event(TouchMsg_t touchMsg)
{
	char rawStr[256];
	char *ptr;
	int i;
	bool writeString = false;

	ptr = rawStr;
	memset(rawStr, 0, sizeof(rawStr));

	for (i=0; i<MAX_TOUCH; ++i) {
		if (touchMsg.touchBitmask[i]) {
			writeString = true;
			snprintf(ptr, sizeof(rawStr) - 1, "x%d:%-5u y%d:%-5u  ", i, touchMsg.touches[i].x, i, touchMsg.touches[i].y);
			ptr = rawStr + strlen(rawStr);
		}
	}
	if (writeString)
		LOG(1, "%s\n", rawStr);
}

__attribute__((format (printf, 4, 5)))
void do_log(unsigned level, const char *filename_p, unsigned lineno, const char *fmt_p, ...)
{
	va_list args;
	char *newFmt_p;
	size_t newFmtSz;

	/* -- preconds -- */
	if (filename_p == NULL)
		return;
	if (fmt_p == NULL)
		return;
	/* -- preconds -- */

	if (level > verbose_G)
		return;

	newFmtSz = strlen(filename_p) + strlen(fmt_p) + 20;
	newFmt_p = malloc(newFmtSz);
	if (newFmt_p == NULL) {
		va_start(args, fmt_p);
		vfprintf(stderr, fmt_p, args);
		va_end(args);
		return;
	}
	snprintf(newFmt_p, newFmtSz, "{%s:%04u} %s", filename_p, lineno, fmt_p);

	va_start(args, fmt_p);
	vfprintf(stderr, newFmt_p, args);
	va_end(args);

	free(newFmt_p);
}
