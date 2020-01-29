/* GStreamer
 * Copyright (C) <2005> Wim Taymans <wim@fluendo.com>
 * Copyright (C) <2005> Nokia Corporation <kai.vehmanen@nokia.com>
 * Copyright (C) <2015> Ethan Funk <ethan@redmountainradio.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
audio/aac or audio/aacp: audio/mpeg,mpegversion={2,4},stream-format={raw, adts, adif, loas}
*/

/**
 * SECTION:element-rspsrc
 * @see_also: rspsink
 *
 * rspsrc is a network source that reads Resilient Streaming Protocol (RSP)
 * media streams from one (or more for clustered) RSP relay servers,
 * multicast groups or a direct UDP port feed conforming to the RSP format.
 *
 * rspsrc requires either the config-json property or the config-file property
 * to be set to configure the network interface for a desired RSP session.
 * Both properties take RSP session configuration data either directly as a jSON
 * string, or as a path to a file which contains the jSON formated RSP session
 * configuration.  See the RSP specification at http://redmountainradio.com/rsp
 * for RSP session configuration details.
 *
 * rspsrc has several additional properties to control how it behaves and interacts
 * with down-stream gstreamer elements:
 *
 * The svr-timeout property sets the time, in seconds, to wait for a streaming
 * server response before moving to the next DNS entry or server in a list
 * provided as part of the RSP configuration.
 *
 * The send-raw property, if true, sends raw, jSON formated RSP meta-data down
 * stream as an GST_TAG_EXTENDED_COMMENT taged with key of 'rsp-meta'. RSP
 * meta-data is similar to gstreamer 'tag' data, only it is not 'flat'.  Meta-data
 * objects can contain meta-data objects within.  This allows for example a single
 * Track object to contain Artist, Album and Title strings all grouped together.
 * Gstreamer tags do not support this grouping, so this property allows a means
 * for the additional data (and grouping) to be passed to an application.
 *
 * The stats property is a read-only property which allows current RSP statistics
 * to be queried.  This includes the following information:
 *	cluster_size	How many relayer servers are being used concurrently
 *
 *	buffer_%		How far ahead (+) or behind (-) we are reading from the ideal
 *					location in the data interleaver.
 *
 *	correction_%	How much forward error correction is being used, in percent.
 *					100% means no additional data errors will be correctable.
 *
 *	err_pkt_%		In reference to the above, percent of data rows (output packets)
 *					that were beyond correction, averaged over one interleaver block.
 *
 *	dup_pkt_%		Percentage of network packets, averaged over one interleaver block,
 *					that were duplicates.  Duplicate packets are not harmful, alowing
 *					multiple internet connections to be used to feed a listener for
 *					redundancy.
 *
 *	bad_pkt_%		Percentage of network packets, averaged over one interleaver block,
 *					That were either not valid RSP packets, or that failed packet
 *					authentications, is the authentication is being used.
 *
 * <refsect2>
 * <title>Examples</title>
 * |[
 * gst-launch-1.0 -t rspsrc config-file=mtnchill128.rsp ! queue leaky=GST_QUEUE_LEAK_UPSTREAM ! decodebin ! autoaudiosink
 * ]| Plays a RSP stream from a relays server, using the configuration expressed in the mtnchill128.rsp file
 * to configure the session.
 * |[
 * gst-launch-1.0 -t rspsrc config-json={\"rspStream\":{\"Name\":\"MtnChill128\",\"IP4\":{\"ReportHost\":\"ss.redmountainradio.com\",\"ReportPort\":5075,\"ReportPeriod\":10}}} ! queue2 max-size-bytes=32768 use-buffering=true ! decodebin ! autoaudiosink
 * ]| Plays a RSP stream from a relays server with the session configured according the json string provided.
 *
 * The file contents of a file based configuration are a json formated string just like the second example.
 * This is useful to pass session properties, such as security keys, which do not pass easily on the command
 * line interface. See http://redmountainradio.com/rsp for session configuration details.
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gstrspsrc.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

GST_DEBUG_CATEGORY_STATIC (rspsrc_debug);
#define GST_CAT_DEFAULT (rspsrc_debug)

#define gst_rspsrc_parent_class parent_class
G_DEFINE_TYPE (Gstrspsrc, gst_rspsrc, GST_TYPE_PUSH_SRC);

#define RSP_DEFAULT_SEND_RAW			FALSE
#define RSP_DEFAULT_SVR_TIMEOUT			10
#define RSP_DEFAULT_CAPS			NULL
#define RSP_DEFAULT_CONF_FILE			NULL
#define RSP_DEFAULT_CONF_JSON			NULL

enum
{
	PROP_0,

	PROP_SVR_TIMEOUT,
	PROP_SEND_RAW,
	PROP_CONF_JSON,
	PROP_CONF_FILE,
	PROP_STATS,
	PROP_LOOP,
	PROP_CAPS,

	PROP_LAST
};

static GstCaps *gst_rspsrc_getcaps (GstBaseSrc * src, GstCaps * filter);
static GstFlowReturn gst_rspsrc_create (GstPushSrc * psrc, GstBuffer ** buf);
static gboolean gst_rspsrc_close (Gstrspsrc * src);
static gboolean gst_rspsrc_unlock (GstBaseSrc * bsrc);
static gboolean gst_rspsrc_send_app_message(Gstrspsrc *rspsrc, gchar *name, gchar *value);
static gboolean gst_rspsrc_send_tag_event(Gstrspsrc *rspsrc, GstTagList * tags);
void gst_rspsrc_convertContentsData (GstBaseSrc * bsrc, cJSON *contents);

static void gst_rspsrc_finalize (GObject * object);

static void gst_rspsrc_set_property (GObject * object, guint prop_id,
											const GValue * value, GParamSpec * pspec);
static void gst_rspsrc_get_property (GObject * object, guint prop_id,
													GValue * value, GParamSpec * pspec);

static GstStateChangeReturn gst_rspsrc_change_state (GstElement * element,
																	GstStateChange transition);

static GstStructure *gst_rspsrc_create_stats(struct rspSession *rsp);

gboolean rspsrcplugin_init(GstPlugin *plugin)
{
	if(!gst_element_register(plugin, "rspsrc", GST_RANK_NONE,  GST_TYPE_rspsrc))
		return FALSE;
	return TRUE;
}

GST_PLUGIN_DEFINE (
	GST_VERSION_MAJOR,
	GST_VERSION_MINOR,
	rspsrc,
	"Receive data via RSP protocol",
	rspsrcplugin_init,
	"0.8",
	"LGPL",
	PACKAGE_NAME,
	"http://redmountainradio.com/rsp"
)

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

static void gst_rspsrc_class_init (GstrspsrcClass * klass)
{
	GObjectClass *gobject_class;
	GstElementClass *gstelement_class;
	GstBaseSrcClass *gstbasesrc_class;
	GstPushSrcClass *gstpushsrc_class;
	
	gobject_class = (GObjectClass *) klass;
	gstelement_class = (GstElementClass *) klass;
	gstbasesrc_class = (GstBaseSrcClass *) klass;
	gstpushsrc_class = (GstPushSrcClass *) klass;
	
	GST_DEBUG_CATEGORY_INIT (rspsrc_debug, "rspsrc", 0, "RSP stream source");
	
	gobject_class->set_property = gst_rspsrc_set_property;
	gobject_class->get_property = gst_rspsrc_get_property;
	gobject_class->finalize = gst_rspsrc_finalize;
	
	gst_element_class_add_pad_template (gstelement_class,
					gst_static_pad_template_get (&src_template));

	g_object_class_install_property (G_OBJECT_CLASS (klass), PROP_SVR_TIMEOUT,
	g_param_spec_int ("svr-timeout", "server timeout",
		"Time, in seconds, to wait for a streaming server response before moving to the next DNS entry or server in a list.",
		0, G_MAXUINT16, RSP_DEFAULT_SVR_TIMEOUT, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_SEND_RAW,
	g_param_spec_boolean ("send-raw", "send raw",
		"Send raw, jSON formated RSP meta-data down stream as an GST_TAG_EXTENDED_COMMENT taged with key of 'rsp-meta'",
		RSP_DEFAULT_SEND_RAW, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_CONF_JSON,
	g_param_spec_string ("config-json", "config string",
		"An RSP session configuration string, in jSON format. Either this property or config-file are required to start an RSP session.",
		RSP_DEFAULT_CONF_JSON, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_CONF_FILE,
	g_param_spec_string ("config-file", "config file",
		"An RSP session configuration file, in jSON format. Either this property or config-json are required to start an RSP session.",
		RSP_DEFAULT_CONF_FILE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_STATS,
	g_param_spec_boxed ("stats", "Statistics",
		"Various RSP related statistics", GST_TYPE_STRUCTURE,
		G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_LOOP,
	g_param_spec_boolean ("loop", "loop",
		"If false (default), will stop after last stream list item has been played, otherwise will loop back to the first stream list entry.",
		FALSE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_CAPS,
	g_param_spec_boxed ("caps", "Caps",
		"The caps of the source pad", GST_TYPE_CAPS,
		G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	gst_element_class_add_pad_template (gstelement_class,
					gst_static_pad_template_get (&src_template));

	gst_element_class_set_static_metadata (gstelement_class,
		"RSP packet receiver", "Source/Network",
		"Receive streaming data over a network via RSP protocol - http://redmountainradio.com/rsp",
		"Ethan Funk <ethan@redmountainradio.com>");

	gstelement_class->change_state = gst_rspsrc_change_state;
	gstbasesrc_class->unlock = gst_rspsrc_unlock;
	gstbasesrc_class->get_caps = gst_rspsrc_getcaps;
	gstpushsrc_class->create = gst_rspsrc_create;
}

static void gst_rspsrc_init (Gstrspsrc * rspsrc)
{
	GST_LOG( "rspsrc_init Start\n");
	rspsrc->rsp = rspSessionNew("gstrspsrc/0.5");
	rspsrc->rsp->referenceDesignator = (void*)rspsrc;

	rspsrc->conf_file = RSP_DEFAULT_CONF_FILE;
	rspsrc->conf_json = RSP_DEFAULT_CONF_JSON;
	rspsrc->svr_timeout = RSP_DEFAULT_SVR_TIMEOUT;
	rspsrc->sendRaw = RSP_DEFAULT_SEND_RAW;
	rspsrc->loop = FALSE;
	rspsrc->caps = RSP_DEFAULT_CAPS;


	/* configure basesrc to be a live source */
	gst_base_src_set_live(GST_BASE_SRC (rspsrc), TRUE);
	/* make basesrc output a segment in time */
	gst_base_src_set_format(GST_BASE_SRC (rspsrc), GST_FORMAT_TIME);
	/* Enable basesrc timestamps on outgoing buffers based on the running_time */
	gst_base_src_set_do_timestamp(GST_BASE_SRC (rspsrc), TRUE);

}
static void
gst_rspsrc_finalize (GObject * object)
{
	Gstrspsrc *rspsrc;

	rspsrc = GST_rspsrc (object);

	if(rspsrc->caps)
		gst_caps_unref(rspsrc->caps);
	rspsrc->caps = RSP_DEFAULT_CAPS;

	G_OBJECT_CLASS (rspsrc)->finalize (object);
}

static GstCaps * gst_rspsrc_getcaps (GstBaseSrc * src, GstCaps * filter)
{
	Gstrspsrc *rspsrc;
	GstCaps *caps, *result;

	rspsrc = GST_rspsrc (src);

	GST_OBJECT_LOCK (src);
	if (caps = rspsrc->caps)
		gst_caps_ref(caps);
	GST_OBJECT_UNLOCK (src);

	if (caps) {
		if (filter) {
			result = gst_caps_intersect_full (filter, caps, GST_CAPS_INTERSECT_FIRST);
			gst_caps_unref (caps);
		} else {
			result = caps;
		}
	} else {
		result = (filter) ? gst_caps_ref (filter) : gst_caps_new_any ();
	}
	return result;
}

static gboolean gst_rspsrc_send_app_message(Gstrspsrc *rspsrc, gchar *name, gchar *value)
{
	GstMessage *msg;
	GstStructure* data;
		GstBus* bus;

	if(bus = gst_element_get_bus(GST_ELEMENT(rspsrc))){
		data = gst_structure_new("rsp-message", name, G_TYPE_STRING, value, NULL);
		msg = gst_message_new_application(rspsrc, data);
		return gst_bus_post(bus, msg);
	}
	return 0;
}

static gboolean gst_rspsrc_send_tag_event(Gstrspsrc *rspsrc, GstTagList * tags)
{
	GstEvent *event;

	if(gst_tag_list_is_empty(tags)){
		gst_tag_list_unref (tags);
		return FALSE;
	}
	event = gst_event_new_tag(tags);
	GST_EVENT_TIMESTAMP(event) = 0;
	return gst_pad_push_event(GST_BASE_SRC_PAD (rspsrc), event);
}

void gst_rspsrc_convertContentsData(GstBaseSrc * bsrc, cJSON *contents)
{
	GstCaps *outcaps;
	cJSON *item;
	const char *typestr;
	char *tagstr;
	int i, count;

	outcaps = NULL;
	if((item = cJSON_GetObjectItem(contents, "Type")) && item->valuestring && (strlen(item->valuestring))){
		typestr = item->valuestring;

		/* Handle old rsp/shoutcast Types */
		if(strcasecmp(typestr, "audio/aac") == 0){
			outcaps = gst_caps_new_empty_simple("audio/mpeg");
			gst_caps_set_simple(outcaps, "mpegversion", G_TYPE_INT, 2, NULL);
			gst_caps_set_simple(outcaps, "stream-format", G_TYPE_STRING, "adts", NULL);
		}else if((strcasecmp(typestr, "audio/aacp") == 0) || (strcasecmp(typestr, "audio/mp4") == 0)){
			outcaps = gst_caps_new_empty_simple("audio/mpeg");
			gst_caps_set_simple(outcaps, "mpegversion", G_TYPE_INT, 4, NULL);
			gst_caps_set_simple(outcaps, "stream-format", G_TYPE_STRING, "adts", NULL);
		}else if(strcasecmp(typestr, "audio/mp3") == 0){
			outcaps = gst_caps_new_empty_simple("audio/mpeg");
			gst_caps_set_simple(outcaps, "mpegversion", G_TYPE_INT, 1, NULL);
			gst_caps_set_simple(outcaps, "layer", G_TYPE_INT, 3, NULL);
		}else if(strcasecmp(typestr, "audio/mpeg") == 0){
			outcaps = gst_caps_new_empty_simple("audio/mpeg");
			/* This may be an old rsp/shoutcast Type, or a gst type... if old rsp/shoutcast, handle accordingly */
			if(cJSON_GetObjectItem(contents, "mpegversion") == NULL){
				/* old rsp/shoutcast type: set up layer and mpegversion properties */
				gst_caps_set_simple(outcaps, "mpegversion", G_TYPE_INT, 1, NULL);
				gst_caps_set_simple(outcaps, "layer", G_TYPE_INT, 3, NULL);
			}
		}else
			outcaps = gst_caps_new_empty_simple(typestr);

		count =	cJSON_GetArraySize(contents);
		for(i=1; i<=count; i++){
			if(item = cJSON_GetArrayItem(contents, i)){
				/* Ignore the Type & mID properties, we already handled Type above, and mID is of no interest */
				if((tagstr = item->string) && (strcmp(tagstr, "Type")) && (strcmp(tagstr, "mID"))){
					/* convert legacy rsp propertys to gstreamer values */
					if(strcmp(tagstr, "SampleRate") == 0)
						tagstr = "rate";
					else if(strcmp(tagstr, "Channels") == 0)
						tagstr = "channels";
					else if(strcmp(tagstr, "kBitRate") == 0){
						tagstr = "bitrate";
						item->valueint = item->valueint * 1024;
					}
					/* pass properties through */
					if(item->type==cJSON_Number)
						gst_caps_set_simple(outcaps, tagstr, G_TYPE_INT, item->valueint, NULL);
					else if(item->type==cJSON_String)
						gst_caps_set_simple(outcaps, tagstr, G_TYPE_STRING, item->valuestring, NULL);
				}
			}
		}

		if(outcaps){
			if(gst_pad_set_caps(bsrc->srcpad, outcaps)){
				GValue value;
				g_value_init(&value, GST_TYPE_CAPS);
				gst_value_set_caps(&value, outcaps);
				gst_rspsrc_set_property(bsrc, PROP_CAPS, &value, NULL);
			}
			gst_caps_unref(outcaps);
		}
	}
}

static GstFlowReturn gst_rspsrc_create (GstPushSrc * psrc, GstBuffer ** buf)
{
	Gstrspsrc *rspsrc;
	GstBuffer *outbuf = NULL;
	GstFlowReturn ret;
	GstMapInfo info;
	GstTagList *tags;
	cJSON *meta;
	cJSON *item;
	cJSON *prop;
	unsigned char err;
	unsigned char discont;
	unsigned char *data, dummy;
	char *msg;
	char *sVal;
	int size;

//	g_print("gst_rspsrc_create entry\n");

	rspsrc = GST_rspsrc(psrc);

	/*	RSP decoding is implemented here using the rspSessionPlayTaskPush function. As it's name implies, rspSessionPlayTaskPush
		is the push mode interface to the rsp decoding code.  In push mode, rspSessionPlayTaskPush will feed data to the caller
		at a rate required to match the average source data rate. It's execution will block as nessesary to keep the data delivered
		at the correct rate. So, rspSessionPlayTaskPush and by extention this function, must be called often enough and without delay
		to allow rspSessionPlayTaskPush to manage the timing.  The caller MUST be prepared for this function to block.

		See the rsp.c source code file for details on a pull mode interface where the calling function is expected handle timing by
		pulling (requesting data blocks) at the correct average rate from the rsp decoder. Pull mode rsp functions will not block.
		However, pulling too fast will eventually result in the rsp interleaver running dry, and pulling too slowly will eventually
		result in the interleaver overflowing (rolling back over on itself - it's a ring-buffer of sorts).

		We start with the data pointer set to non-zero, telling the rspSessionPlayTaskPush function to
		first check for immediately available data before it calls any network/timing functions which might block.
		If no data is immediatly available, rspSessionPlayTaskPush will null this pointer such that subsequent calls
		to rspSessionPlayTaskPush are allowed to wait for data to become available.  Note that the actual pointer address
		value is unimportant on entry to rspSessionPlayTaskPush, it is mearly acting as a flag.
	*/
	data = &dummy;
	discont = 0;
	GST_OBJECT_LOCK(rspsrc);
	while(rspsrc->state > 1){
		if(rspsrc->state == 2){
			// if run state is load-next
			if((err = rspSessionConfigNextJSON(rspsrc->rsp, &rspsrc->current)) == RSP_ERROR_END){
				if(rspsrc->loop){
					// back to the first item in the stream list
					rspsrc->current = rspsrc->rspSection;
					GST_OBJECT_UNLOCK(rspsrc);
					gst_rspsrc_send_app_message(rspsrc, "status", "end of stream-list, looping back to first.");
					GST_OBJECT_LOCK(rspsrc);
					continue;
				}else{
					// no more entries to try
					rspsrc->state = 0;
					GST_OBJECT_UNLOCK(rspsrc);
					gst_rspsrc_send_app_message(rspsrc, "status", "end of stream-list");
					GST_OBJECT_LOCK(rspsrc);
					break;
				}
			}

			rspSessionClear(rspsrc->rsp, TRUE);
			rspsrc->state = 3;			/* next entry loaded: set run state to "next network" */
			GST_OBJECT_UNLOCK(rspsrc);
			gst_rspsrc_send_app_message(rspsrc, "status", "loading next stream");
			GST_OBJECT_LOCK(rspsrc);

			if(err != RSP_ERROR_NONE){
				// A problem with the current rspStream list entry... try another
				continue;
			}
		}
		if(rspsrc->state == 3){
			GST_OBJECT_UNLOCK(rspsrc);
			gst_rspsrc_send_app_message(rspsrc, "status", "trying next address");
			GST_OBJECT_LOCK(rspsrc);

			if(rspSessionNextNetworkSetup(rspsrc->rsp, rspsrc->rsp->timeout, NULL) != RSP_ERROR_NONE){
				// no more network records to try
				rspsrc->state = 2;		/* set run state back to "load-next" */
				continue;
			}
			// send a request to relay server or receiver report host to start sending stream packets... direct source will ignore this request
			if(rspPacketRecvrRequestSend(rspsrc->rsp, NULL, TRUE) != RSP_ERROR_NONE)
				continue;
			rspsrc->state = 4;			/* next network loaded: set run state to "discover format" */
			GST_OBJECT_UNLOCK(rspsrc);
			gst_rspsrc_send_app_message(rspsrc, "status", "discovering format");
		}else
			GST_OBJECT_UNLOCK(rspsrc);
		// if we get here, we are in discover, buffer or play run state
		size = rspSessionPlayTaskPush(rspsrc->rsp, &msg, &meta, &data, (rspsrc->state == 6 ? 0 : 1), 0.0);
		GST_OBJECT_LOCK(rspsrc);
		if((size == -3) || (size == -4)){
			// We have not received valid data in time-out period OR there was a socker error... handle!
			if(rspsrc->state > 1)
				// set run state to next network ***If*** run state is has not been set to flushing or idle from a different thread
				rspsrc->state = 3;
			continue;
		}
		if((rspsrc->state == 4) && rspsrc->rsp->interleaver){
			rspsrc->state = 5;	/* format discovered: set run state to "buffering" */
			GST_OBJECT_UNLOCK(rspsrc);
			gst_rspsrc_send_app_message(rspsrc, "status", "buffering");
			GST_OBJECT_LOCK(rspsrc);
		}
		if((rspsrc->state > 4) && !rspsrc->rsp->interleaver){
			rspsrc->state = 4;	/* format has changed: set run state to "discovering format" */
			GST_OBJECT_UNLOCK(rspsrc);
			gst_rspsrc_send_app_message(rspsrc, "status", "format changed, re-discovering");
		}else
			GST_OBJECT_UNLOCK(rspsrc);

		if(meta){
			/* handle new meta data */

			/* if sendRaw is true, send all metadata we get in the RSP native jSON format as an GST_TAG_EXTENDED_COMMENT tag */
			char *metaStr;
			if(rspsrc->sendRaw && (metaStr = cJSON_PrintUnformatted(meta))){
				char *strVal = NULL;
				appendstr(&strVal, "rsp-meta=");
				appendstr(&strVal, metaStr);
				free(metaStr);
				tags = gst_tag_list_new_empty();
				gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_EXTENDED_COMMENT, strVal, NULL);
				gst_rspsrc_send_tag_event(rspsrc, tags);
				free(strVal);
			}

			/* see if this is track "item." If so, reformat as gStreamer tag Artist, Title, etc., tags */
			if((item = cJSON_GetObjectItem(meta, "Item")) || (item = cJSON_GetObjectItem(meta, "item"))){
				// set Artist, Album, Title, etc. properties
				tags = gst_tag_list_new_empty();
				// look for entires that are lists, not values
				if(prop = item->child){
					char *metaStr;
					char *strVal;
					do{
						if(prop->child && prop->string){
							if(metaStr = cJSON_PrintUnformatted(prop)){
								strVal = NULL;
								appendstr(&strVal, prop->string);
								appendstr(&strVal, "=");
								appendstr(&strVal, metaStr);
								free(metaStr);
								gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_EXTENDED_COMMENT, strVal, NULL);
								free(strVal);
							}
						}
					}while(prop = prop->next);
				}

				sVal = "[None]";
				if(prop = cJSON_GetObjectItem(item, "Artist")){
					if(prop->valuestring && (strlen(prop->valuestring)))
						sVal = prop->valuestring;
				}
				gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_ARTIST, sVal, NULL);

				sVal = "[None]";
				if(prop = cJSON_GetObjectItem(item, "Name")){
					if(prop->valuestring && (strlen(prop->valuestring)))
						sVal = prop->valuestring;
				}
				gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_TITLE, sVal, NULL);

				sVal = "[None]";
				if(prop = cJSON_GetObjectItem(item, "Album")){
					if(prop->valuestring && (strlen(prop->valuestring)))
						sVal = prop->valuestring;
				}
				gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_ALBUM, sVal, NULL);

				if(prop = cJSON_GetObjectItem(item, "Track")){
					char tmp[32];
					snprintf(tmp, sizeof(tmp), "%d", prop->valueint);
					gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_TRACK_NUMBER, tmp, NULL);
				}

				if(prop = cJSON_GetObjectItem(item, "ISRC")){
					if(prop->valuestring && (strlen(prop->valuestring))){
						sVal = prop->valuestring;
						gst_tag_list_add(tags, GST_TAG_MERGE_REPLACE, GST_TAG_ISRC, sVal, NULL);
					}
				}
				
				gst_rspsrc_send_tag_event(rspsrc, tags);
			}

			if((item = cJSON_GetObjectItem(meta, "Content")) || (item = cJSON_GetObjectItem(meta, "content"))){
				/* new stream content info... assume the stream has stopped and restarted */
				discont = 1;
				/* pass content info along to gstreamer as a source pad capability */
				gst_rspsrc_convertContentsData(rspsrc, item);
			}

			cJSON_Delete(meta);
		}
		if(msg){
			/* handle server message */
            		gst_rspsrc_send_app_message(rspsrc, "server message", msg);
			free(msg);
		}
		if(size < 0){
			GST_OBJECT_LOCK(rspsrc);
			if((rspsrc->state > 1) && (rspsrc->state != 5)){
				rspsrc->state = 5;	/* break in stream: set run state to "buffering" */
				GST_OBJECT_UNLOCK(rspsrc);
                		gst_rspsrc_send_app_message(rspsrc, "status", "buffering");
			}else
				GST_OBJECT_UNLOCK(rspsrc);
		}

		/* Handle decoded stream data */
		if((size > 0) && (rspsrc->caps != NULL)){
			/* Only pass data after we have determined the correct content type (caps) */
			ret = GST_BASE_SRC_CLASS(parent_class)->alloc(GST_BASE_SRC_CAST(rspsrc), -1, size, &outbuf);
			if(ret != GST_FLOW_OK){
				gst_rspsrc_send_app_message(rspsrc, "error", "gst buffer allocation error");
				return ret;
			}
			gst_buffer_map(outbuf, &info, GST_MAP_WRITE);
			/* copy from the rsp session data buffer, to the gstreamer buffer */
			memcpy(info.data, data, info.size);
			/* and finalize the gstreamer buffer, and update state */
			GST_OBJECT_LOCK(rspsrc);
			if((rspsrc->state > 1) && (rspsrc->state != 6)){
				if(rspsrc->state == 5){
					discont = 1;
					rspsrc->state = 6;	/* stream playing: set run state to "playing" */
					GST_OBJECT_UNLOCK(rspsrc);
                   			gst_rspsrc_send_app_message(rspsrc, "status", "playing");
				}else
                   			 GST_OBJECT_UNLOCK(rspsrc);
			}else
                		GST_OBJECT_UNLOCK(rspsrc);
			if(discont){
				GST_BUFFER_FLAG_SET(outbuf, GST_BUFFER_FLAG_DISCONT);
				GST_BUFFER_FLAG_SET(outbuf, GST_BUFFER_FLAG_RESYNC);
			}else{
				GST_BUFFER_FLAG_UNSET(outbuf, GST_BUFFER_FLAG_DISCONT);
				GST_BUFFER_FLAG_UNSET(outbuf, GST_BUFFER_FLAG_RESYNC);
			}
			gst_buffer_unmap(outbuf, &info);
			*buf = GST_BUFFER_CAST(outbuf);
			return GST_FLOW_OK;
		}
		GST_OBJECT_LOCK(rspsrc);
	}
	/* we get here if the run state is idle or flushing
	send a request to relay server to stop sending stream packets. This is a harmeless call if session is already closed. */
	rspPacketRecvrRequestSend(rspsrc->rsp, NULL, FALSE);
	/* and return appropriate result */
	gst_rspsrc_send_app_message(rspsrc, "status", "stopping");
	if(rspsrc->state == 1){
		GST_OBJECT_UNLOCK(rspsrc);
		return GST_FLOW_FLUSHING;
	}else{
		GST_OBJECT_UNLOCK(rspsrc);
		return GST_FLOW_EOS;
	}
}

static void
gst_rspsrc_set_property(GObject * object, guint prop_id, const GValue * value, GParamSpec * pspec)
{
	Gstrspsrc *rspsrc = GST_rspsrc(object);
	GST_LOG( "set_property Start\n");
	switch (prop_id){
		case PROP_SVR_TIMEOUT:
			rspsrc->svr_timeout = g_value_get_int(value);
			break;

		case PROP_SEND_RAW:
			rspsrc->sendRaw = g_value_get_boolean(value);
			break;

		case PROP_CONF_JSON:
			if(rspsrc->conf_json)
				free(rspsrc->conf_json);
			rspsrc->conf_json = g_value_dup_string(value);
			break;

		case PROP_CONF_FILE:
			if(rspsrc->conf_file)
				free(rspsrc->conf_file);
			rspsrc->conf_file = g_value_dup_string(value);
			break;

		case PROP_LOOP:
			rspsrc->loop = g_value_get_boolean(value);
			break;

		case PROP_CAPS:
		{
			const GstCaps *new_caps_val = gst_value_get_caps(value);
			GstCaps *new_caps;
			GstCaps *old_caps;

			if(new_caps_val != NULL)
				new_caps = gst_caps_copy(new_caps_val);

			GST_OBJECT_LOCK(rspsrc);
			old_caps = rspsrc->caps;
			rspsrc->caps = new_caps;
			GST_OBJECT_UNLOCK (rspsrc);
			if(old_caps)
				gst_caps_unref (old_caps);
			gst_pad_mark_reconfigure (GST_BASE_SRC_PAD (rspsrc));
			break;
		}

		default:
			break;
	}
}

static void
gst_rspsrc_get_property (GObject * object, guint prop_id, GValue * value, GParamSpec * pspec)
{
	Gstrspsrc *rspsrc = GST_rspsrc(object);

	switch (prop_id){
		case PROP_SVR_TIMEOUT:
			g_value_set_int(value, rspsrc->svr_timeout);
			break;

		case PROP_SEND_RAW:
			g_value_set_boolean(value, rspsrc->sendRaw);
			break;

		case PROP_CONF_JSON:
			g_value_set_string(value, rspsrc->conf_json);
			break;

		case PROP_CONF_FILE:
			g_value_set_string(value, rspsrc->conf_file);
			break;

		case PROP_LOOP:
			g_value_set_boolean(value, rspsrc->loop);
			break;

		case PROP_CAPS:
			GST_OBJECT_LOCK(rspsrc);
			gst_value_set_caps(value, rspsrc->caps);
			GST_OBJECT_UNLOCK(rspsrc);
			break;

		case PROP_STATS:
			g_value_take_boxed(value, gst_rspsrc_create_stats(rspsrc->rsp));
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}

}

/* create a rsp session configured according to the provided jSON string or file */
static gboolean gst_rspsrc_open (Gstrspsrc * src)
{
	cJSON *root;
	/* NOT THREAD SAFE: NO OTHER THERADS SHOULD BE USING THE RSP SESSION WHILE THIS FUNCTION IS CALLED */
	if(src->conf_file){
		// Open the specified stream configuration file
		FILE *confFile = fopen(src->conf_file, "r");
		if(confFile == NULL){
		    GST_ELEMENT_ERROR (src, RESOURCE, OPEN_READ, (""),
				("File open error on the specified config file: %s", src->conf_file));
			gst_rspsrc_close(src);
			return FALSE;
		}
		if((src->rspSection = rspSessionReadConfigFile(confFile)) == NULL){
			fclose(confFile);
			GST_ELEMENT_ERROR (src, RESOURCE, SETTINGS, (""),
				 ("RSP session configuration failed"));
			gst_rspsrc_close(src);
			return FALSE;
		}
		fclose(confFile);
	}else if(src->conf_json){
		// Read jSON format configuration from stdin
		if((root = cJSON_Parse(src->conf_json)) == NULL){
			GST_ELEMENT_ERROR (src, RESOURCE, SETTINGS, (""),
				("Configuration parse error"));
			gst_rspsrc_close(src);
			return FALSE;
		}
		if((src->rspSection = cJSON_DetachItemFromObject(root, "rspStream")) == NULL){
			cJSON_Delete(root);
			GST_ELEMENT_ERROR (src, RESOURCE, SETTINGS, (""),
				("Configuration missing 'rspStream' section"));
			gst_rspsrc_close(src);
			return FALSE;
		}
		cJSON_Delete(root);
	}else{
		GST_ELEMENT_ERROR (src, RESOURCE, SETTINGS, (NULL),
			("Configuration missing.  Either 'conf-file' or 'conf-str' must be specified."));
		gst_rspsrc_close(src);
		return FALSE;

	}
	src->current = src->rspSection;
	// set run state to load-next
	src->state = 2;
	gst_rspsrc_send_app_message(src, "status", "source configured");
	return TRUE;
}

static gboolean gst_rspsrc_unlock(GstBaseSrc * bsrc)
{
	Gstrspsrc *src;
	src = GST_rspsrc (bsrc);
	GST_OBJECT_LOCK(src);
	src->state = 1;
	if(src->rsp->clientSocket > -1){
		// closing the client socket will cause any waiting network reads to terminate with an error
		// such that the create function, if blocked at the time of this call will then notice the
		// will unblock due to the error, notice the state change and act accordingly.
		close(src->rsp->clientSocket);
		src->rsp->clientSocket = -1;
	}
	GST_OBJECT_UNLOCK(src);
	return TRUE;
}

static gboolean gst_rspsrc_close (Gstrspsrc * src)
{
	/* NOT THREAD SAFE: NO OTHER THERADS SHOULD NOT BE USING THE RSP SESSION WHILE THIS FUNCTION IS CALLED */
	rspSessionFree(src->rsp);
	if(src->conf_json)
		free(src->conf_json);
	if(src->conf_file)
		free(src->conf_file);
	if(src->rspSection)
		cJSON_Delete(src->rspSection);
	return TRUE;
}

static GstStateChangeReturn gst_rspsrc_change_state (GstElement * element, GstStateChange transition)
{
	Gstrspsrc *src;
	GstStateChangeReturn result;

	src = GST_rspsrc (element);

	switch (transition) {
		case GST_STATE_CHANGE_NULL_TO_READY:
			if(!gst_rspsrc_open(src))
				goto open_failed;
			break;
		case GST_STATE_CHANGE_READY_TO_NULL:
			gst_rspsrc_close(src);
			break;
		default:
			break;
	}

	if((result = GST_ELEMENT_CLASS(parent_class)->change_state (element, transition)) == GST_STATE_CHANGE_FAILURE)
		goto failure;
	return result;
	/* ERRORS */
open_failed:
	{
		GST_DEBUG_OBJECT (src, "failed to load RSP configuration");
		return GST_STATE_CHANGE_FAILURE;
	}
failure:
	{
		GST_DEBUG_OBJECT (src, "parent failed state change");
		return result;
	}
}

static GstStructure * gst_rspsrc_create_stats(struct rspSession *rsp)
{
	GstStructure *s;
	s = gst_structure_new("application/x-rsp-stats",
						   "cluster_size", G_TYPE_UINT, rsp->relay_cluster,
						   "buffer_%", G_TYPE_FLOAT, rspSessionGetBalance(rsp) * 100.0,
						   "correction_%", G_TYPE_FLOAT, rsp->FECStat / rsp->FECroots * 100.0,
						   "err_pkt_%", G_TYPE_FLOAT, rsp->ErrStat * 100.0,
						   "dup_pkt_%", G_TYPE_FLOAT, rsp->DupStat * 100.0,
						   "bad_pkt_%", G_TYPE_FLOAT, rsp->BadStat * 100.0, NULL);
	return s;
}
