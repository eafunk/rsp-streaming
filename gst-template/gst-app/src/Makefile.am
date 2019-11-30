# name of your binary
bin_PROGRAMS = gst_rspplayer

# list of source files
# the prefix is the name of the binary
gst_rspplayer_SOURCES = main.c gstrspsrc.c rs.c rsp.c cJSON.c

# list of headers we're not going to install
noinst_HEADERS = 

# our CFLAGS and LDFLAGS used for compiling and linking
# make sure you prefix these with the name of your binary
gst_rspplayer_CFLAGS = $(GST_CFLAGS)
gst_rspplayer_LDFLAGS = $(GST_LIBS) -lm -lcrypto
