#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT(fileMonitor, 1.0, 2008rengaojun@sina.com)‏
AM_INIT_AUTOMAKE(fileMonitor, 1.0)‏
AC_CONFIG_SRCDIR([fileMonitor.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([ftruncate memset strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
