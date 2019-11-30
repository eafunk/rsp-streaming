# Note: plugindir is set in configure

##############################################################################
# TODO: change libgstplugin.la to something else, e.g. libmysomething.la     #
##############################################################################
plugin_LTLIBRARIES = libgstrspsrc.la

##############################################################################
# TODO: for the next set of variables, name the prefix if you named the .la, #
#  e.g. libmysomething.la => libmysomething_la_SOURCES                       #
#                            libmysomething_la_CFLAGS                        #
#                            libmysomething_la_LIBADD                        #
#                            libmysomething_la_LDFLAGS                       #
##############################################################################

# sources used to compile this plug-in
libgstrspsrc_la_SOURCES = gstrspsrc.c gstrspsrc.h rs.c rs.h rsp.c rsp.h cJSON.c cJSON.h

# compiler and linker flags used to compile this plugin, set in configure.ac
libgstrspsrc_la_CFLAGS = $(GST_CFLAGS)
libgstrspsrc_la_LIBADD = $(GST_LIBS) -lcrypto
libgstrspsrc_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS)
libgstrspsrc_la_LIBTOOLFLAGS = --tag=disable-static

# headers we need but don't want installed
noinst_HEADERS = gstrspsrc.h
