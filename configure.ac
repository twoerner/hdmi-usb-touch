dnl Copyright (C) 2016  Trevor Woerner <twoerner@gmail.com>
dnl LICENSE: MIT (see COPYING.MIT file)

AC_INIT([HDMI USB Touch], 0.1.0, [twoerner@gmail.com], hdmi-usb-touch)
AC_CONFIG_SRCDIR(src/hdmi-usb-touch.c)
AC_CONFIG_AUX_DIR(cfg)
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-bzip2 1.9])
AM_CONFIG_HEADER(cfg/config.h)

SUBDIRS="src doodles"

dnl **********************************
dnl checks for programs
dnl **********************************
AC_PROG_CC
AC_PROG_CPP

AC_PROG_MAKE_SET

AC_PROG_INSTALL
AC_PROG_LN_S

AC_CHECK_PROG(strip, strip, strip, :)

dnl **********************************
dnl checks for libraries
dnl **********************************
AC_CHECK_LIB(udev, udev_new,,AC_MSG_ERROR([can't find udev]),) 

dnl **********************************
dnl checks for header files
dnl **********************************
AC_HEADER_STDC
AC_CHECK_HEADERS(stdio.h stdlib.h stdint.h stdbool.h stdarg.h string.h,,AC_MSG_ERROR(missing header))
AC_CHECK_HEADERS(unistd.h signal.h fcntl.h limits.h errno.h getopt.h setjmp.h,,AC_MSG_ERROR(missing header))
AC_CHECK_HEADERS(sys/select.h sys/time.h sys/types.h sys/stat.h sys/ioctl.h,,AC_MSG_ERROR(missing header))
AC_CHECK_HEADERS(linux/uinput.h linux/input.h,,AC_MSG_ERROR(missing header))
AC_CHECK_HEADERS(libudev.h,,AC_MSG_ERROR(missing header))

dnl **********************************
dnl output
dnl **********************************
AC_SUBST(SUBDIRS)
AC_OUTPUT(Makefile
cfg/Makefile
doodles/Makefile
src/Makefile)
