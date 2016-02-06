/*
 * Copyright (C) 2016  Trevor Woerner <twoerner@gmail.com>
 * LICENSE: MIT (see COPYING.MIT)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libudev.h>
#include <getopt.h>

// forward refs
static void usage(const char *cmd_p);
static int process_cmdline_args(int argc, char *argv[]);
static int enumerate_devices(struct udev *udev_p);

// globals
char *class_pG = NULL;
char *classDefault_pG = "usbmisc";

int
main (int argc, char *argv[])
{
	int retInt;
	struct udev *udev_p;

	retInt = process_cmdline_args(argc, argv);
	if (retInt != 0)
		return 1;

	udev_p = udev_new();
	if (udev_p == NULL) {
		perror("udev_new():");
		return 1;
	}

	retInt = enumerate_devices(udev_p);
	if (retInt != 0) {
		fprintf(stderr, "enumerate error\n");
		goto cleanup;
	}

	retInt = 0;

cleanup:
	udev_unref(udev_p);
	if (class_pG != NULL)
		free(class_pG);
	return retInt;
}

static int
enumerate_devices(struct udev *udev_p)
{
	int retInt = 0, iteration = 0;
	struct udev_enumerate *udevEnumerate_p;
	struct udev_list_entry *udevAllDevices_p, *udevOneDevice_p;

	udevEnumerate_p = udev_enumerate_new(udev_p);
	if (udevEnumerate_p == NULL) {
		perror("udev_enumerate_new():");
		return errno;
	}

	if (class_pG == NULL) {
		printf("class: %s\n", classDefault_pG);
		retInt = udev_enumerate_add_match_subsystem(udevEnumerate_p, classDefault_pG);
	}
	else {
		printf("class: %s\n", class_pG);
		retInt = udev_enumerate_add_match_subsystem(udevEnumerate_p, class_pG);
	}
	if (retInt != 0) {
		perror("udev_enumerate_add_match_subsystem():");
		return retInt;
	}

	retInt = udev_enumerate_scan_devices(udevEnumerate_p);
	if (retInt != 0) {
		perror("udev_enumerate_scan_devices():");
		return retInt;
	}

	udevAllDevices_p = udev_enumerate_get_list_entry(udevEnumerate_p);
	udev_list_entry_foreach(udevOneDevice_p, udevAllDevices_p) {
		const char *path_p;
		struct udev_device *device_p, *parent_p;

		++iteration;

		path_p = udev_list_entry_get_name(udevOneDevice_p);
		device_p = udev_device_new_from_syspath(udev_p, path_p);
		if (device_p == NULL)
			continue;

		printf("%d\n", iteration);
		printf("\tdevice: %s\n", udev_device_get_sysname(device_p));
		printf("\tdevice path: %s\n", path_p);
		printf("\tdevice node: %s\n", udev_device_get_devnode(device_p));

		parent_p = udev_device_get_parent_with_subsystem_devtype(device_p, "usb", "usb_device");
		if (parent_p == NULL) {
			udev_device_unref(device_p);
			continue;
		}
		printf("\tparent: %s\n", udev_device_get_sysname(parent_p));
		printf("\tidVendor:%s idProduct:%s manufacturer:%s product:%s serial:%s\n",
				udev_device_get_sysattr_value(parent_p, "idVendor"),
				udev_device_get_sysattr_value(parent_p, "idProduct"),
				udev_device_get_sysattr_value(parent_p, "manufacturer"),
				udev_device_get_sysattr_value(parent_p, "product"),
				udev_device_get_sysattr_value(parent_p, "serial"));

		udev_device_unref(device_p);
	}

	if (iteration == 0)
		printf("-- no devices --\n");

	udev_enumerate_unref(udevEnumerate_p);
	return retInt;
}

static void
usage(const char *cmd_p)
{
	printf("Usage: %s [options]\n", cmd_p);
	printf("  options:\n");
	printf("    -h|--help                Print this help and exit successfully.\n");
	printf("    -c|--class <subsystem>   Use <class> instead of default \"%s\".\n", classDefault_pG);
	printf("\n");
}

static int
process_cmdline_args (int argc, char *argv[])
{
	int c, retInt = 0;
	struct option longOpts[] = {
		{"help", no_argument, NULL, 'h'},
		{"class", required_argument, NULL, 'c'},
		{NULL, 0, NULL, 0},
	};

	for (;;) {
		c = getopt_long(argc, argv, "hc:", longOpts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage (argv[0]);
				exit (0);

			case 'c':
				class_pG = strdup (optarg);
				break;

			default:
				fprintf (stderr, "unhandled cmdline arg: %c (0x%02x)\n", optopt, optopt);
				retInt = 1;
				break;
		}
	}

	return retInt;
}
