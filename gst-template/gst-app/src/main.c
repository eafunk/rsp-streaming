#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gst/gst.h>
#include "gstrspsrc.h"

static gboolean rspsrcplugin_init(GstPlugin *plugin);

void play_file(const gchar *filepath, const gchar *confStr)
{
	GstElement *pipeline;
	GstElement *src, *q1;
	GstMessage *msg = NULL;
	GError *error = NULL;
	GstBus *bus;
	gboolean buffering = FALSE;

	/* initialise the gstreamer system */
	gst_init(NULL, NULL);

    	/* register my custom plugin */
	rspsrcplugin_init(NULL);

	/* create pipeline */
// 	pipeline = gst_parse_launch("rspsrc name=rsp_source ! queue leaky=2 name=theQ1 ! decodebin use-buffering='false' "
//									"! queue2 use-buffering='true' name=theQ2 ! autoaudiosink", &error);

	pipeline = gst_parse_launch("rspsrc name=rsp_source loop='true' ! decodebin ! queue2 use-buffering=TRUE "
								"max-size-time=10000000000 name=theQ1 ! autoaudiosink", &error);

//	pipeline = gst_parse_launch("rspsrc name=rsp_source loop=TRUE ! decodebin use-buffering=TRUE ! autoaudiosink", &error);


	if(!pipeline) {
		g_print ("\nPipeline parse error: %s\n", error->message);
		return;
	}

	/* get queue element from pipeline, by name */
	q1 = gst_bin_get_by_name(GST_BIN (pipeline), "theQ1");
	/* get source element from pipeline, by name */
	src = gst_bin_get_by_name(GST_BIN (pipeline), "rsp_source");
	/* set rsp stream config file, or config-json, etc */
	if(filepath)
		g_object_set(src, "config-file", filepath, NULL);
	if(confStr)
		g_object_set(src, "config-json", confStr, NULL);
	g_object_set(src, "send-raw", 1, NULL);

	/* get the pipeline's bus, for receiving messages, tags, etc. */
	bus = gst_element_get_bus(pipeline);

	/* and start the pipeline running */
	gst_element_set_state(GST_ELEMENT(pipeline), GST_STATE_PLAYING);

	GstStructure *stats_struct;
	unsigned int cluster_cnt;
	float fec;
	float err;
	float bad;
	float dup;
	float buffer;

	while(1){
		if(msg = gst_bus_poll(bus, GST_MESSAGE_TAG | GST_MESSAGE_APPLICATION | GST_MESSAGE_EOS | GST_MESSAGE_BUFFERING |
																					GST_MESSAGE_CLOCK_LOST | GST_MESSAGE_ERROR, GST_SECOND)){
			if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_ERROR){
				GError *err = NULL;
				gchar *dbg_str = NULL;

				gst_message_parse_error (msg, &err, &dbg_str);
				g_printerr("\nERROR: %s\n%s\n", err->message,
	                	        (dbg_str) ? dbg_str : "(no debugging information)");
				g_error_free(err);
				g_free (dbg_str);
	           		gst_message_unref(msg);
	            		continue;
			}
			if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_EOS){
				g_print ("\nAudio Finished.\n");
				gst_message_unref(msg);
				break;
			}
			if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_CLOCK_LOST){
				g_print("GST_MESSAGE_CLOCK_LOST");
				gst_element_set_state(GST_ELEMENT(pipeline), GST_STATE_PAUSED);
				gst_element_set_state(GST_ELEMENT(pipeline), GST_STATE_PLAYING);
				continue;
			}
			if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_BUFFERING){
				gint percent;

				gst_message_parse_buffering (msg, &percent);
					if(percent == 100){
					if(buffering){
						buffering = FALSE;
						gst_element_set_state (pipeline, GST_STATE_PLAYING);
						g_print ("\nAudio running\n");
					}
				}else{
					if(!buffering){
						buffering = TRUE;
						gst_element_set_state (pipeline, GST_STATE_PAUSED);
						g_print ("\nAudio buffering\n");
					}
				}
				continue;
			}	
			if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_TAG){
				GstTagList *tags = NULL;
				gchar *seg, *tag_str = NULL;
	
				gst_message_parse_tag(msg, &tags);
				if(gst_tag_list_get_string(tags, GST_TAG_EXTENDED_COMMENT, &tag_str)){
					if(strstr(tag_str, "rsp-meta=") == tag_str){
						seg = tag_str + 9;
						g_print("\nMetadata:%s\n", seg);
					}
					g_free(tag_str);
				}
				gst_tag_list_unref(tags);
				gst_message_unref(msg);
				continue;
			}
			if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_APPLICATION){
				const GstStructure *data;
				gchar *str;
	
				if(data = gst_message_get_structure(msg)){
					if(str = gst_structure_get_string(data, "status"))
						g_print("\nNetwork:%s\n", str);
					if(str = gst_structure_get_string(data, "server message"))
						g_print("\nServer:%s\n", str);
					if(str = gst_structure_get_string(data, "error"))
						g_print("\nRSP error:%s\n", str);
				}
				gst_message_unref(msg);
				continue;
			}
		}
		g_object_get(src, "stats", &stats_struct, NULL);
		if(stats_struct){
			if(gst_structure_get(stats_struct,
					"cluster_size", G_TYPE_UINT, &cluster_cnt,
					"buffer_%", G_TYPE_FLOAT, &buffer,
					"correction_%", G_TYPE_FLOAT, &fec,
					"err_pkt_%", G_TYPE_FLOAT, &err,
					"dup_pkt_%", G_TYPE_FLOAT, &dup,
					"bad_pkt_%", G_TYPE_FLOAT, &bad, NULL))
				g_print("\33[2K\rrsp: Cluster=%d Buffer=%.0f Fixed=%.0f Err=%.0f Bad=%.0f Dup=%.0f",
			cluster_cnt, buffer, fec, err, bad, dup);
		}

		guint64 qTime1;
		float qSec1;
		g_object_get(q1, "current-level-time", &qTime1, NULL);
		qSec1 = qTime1 * 1e-9;
		g_print(" qTime=%f", qSec1);

	}


	/* shut down and free everything */
	gst_element_set_state(pipeline, GST_STATE_NULL);
	gst_object_unref(pipeline);
	gst_object_unref(bus);
}

int main(int argc, char *argv[])
{
	if(argc == 2){
		if(strcmp(argv[1], "-") == 0){
			size_t count, total;
			char *text = (char *)malloc(257);
			total = 0;
			while(1){
				count = fread(text+total, 1, 256, stdin);
				total = total + count;
				if(count == 256)
					text = realloc(text, total + 257);
				else
					break;
			}
			text[total] = 0;
			play_file(NULL, text);
			return 0;
		}else{
			play_file(argv[1], NULL);
			return 0;
		}
	}
	fprintf(stderr, "Please provide a single command argument: a file path/name to an rsp listen file,\n");
	fprintf(stderr, "or - to read a jSON formatted rsp listen string from stdin.\n");
	return 0;
}
