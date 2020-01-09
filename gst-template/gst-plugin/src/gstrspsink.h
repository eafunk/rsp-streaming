/* GStreamer
 * Copyright (C) <1999> Erik Walthinsen <omega@cse.ogi.edu>
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


#ifndef __GST_rspsink_H__
#define __GST_rspsink_H__

#include <glib.h>
#include <gst/gst.h>
#include <gst/base/gstbasesink.h>
#include <gio/gio.h>
#include "rsp.h"

G_BEGIN_DECLS

#define GST_TYPE_rspsink 		(gst_rspsink_get_type())
#define GST_rspsink(obj) 		(G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_rspsink,Gstrspsink))
#define GST_rspsink_CLASS(klass) 	(G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_rspsink,GstrspsinkClass))
#define GST_IS_rspsink(obj) 		(G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_rspsink))
#define GST_IS_rspsink_CLASS(klass) 	(G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_rspsink))
#define GST_rspsink_CAST(obj) 		((Gstrspsink *)(obj))

typedef struct _Gstrspsink Gstrspsink;
typedef struct _GstrspsinkClass GstrspsinkClass;

struct destination {
	struct destination	*next;
	struct sockaddr_in6 sock_addr;
	int socket;					// will be sent either to a common (reused) udp socket or a custom 
									// socket with proper ttl set if the destination is a multicast group
};

struct _Gstrspsink {
	GstBaseSinkClass parent;

	struct rspSession *rsp;
	unsigned char dataFrame[255];
	unsigned char frag_offset;
	char *curMetaStr;
	unsigned int metaPos;
	struct destination *destinations;
	int rsp_socket4;
	int rsp_socket6;
	GCancellable  *cancellable;

	/* properties */
	gchar			*prop_sendto;
	gint			prop_ttl;
	gint			prop_tos;
	gchar			*prop_bindip4;
	gchar			*prop_bindip6;
	gint			prop_fec;
	gint			prop_payload;
	gint			prop_interleaving;
	gboolean		prop_crc;
	gboolean		prop_rs;
	gchar			*prop_key_file;
	gchar			*prop_key_pw;

};

struct _GstrspsinkClass {
  GstBaseSinkClass parent_class;
};

GType gst_rspsink_get_type(void);

G_END_DECLS


#endif /* __GST_rspsrc_H__ */
