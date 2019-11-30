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


#ifndef __GST_rspsrc_H__
#define __GST_rspsrc_H__

#include <glib.h>
#include <gst/gst.h>
#include <gst/base/gstpushsrc.h>
#include <gio/gio.h>
#include "rsp.h"

G_BEGIN_DECLS

#define GST_TYPE_rspsrc 		(gst_rspsrc_get_type())
#define GST_rspsrc(obj) 		(G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_rspsrc,Gstrspsrc))
#define GST_rspsrc_CLASS(klass) 	(G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_rspsrc,GstrspsrcClass))
#define GST_IS_rspsrc(obj) 		(G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_rspsrc))
#define GST_IS_rspsrc_CLASS(klass) 	(G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_rspsrc))
#define GST_rspsrc_CAST(obj) 		((Gstrspsrc *)(obj))

typedef struct _Gstrspsrc Gstrspsrc;
typedef struct _GstrspsrcClass GstrspsrcClass;

struct _Gstrspsrc {
  GstPushSrc parent;

  cJSON *rspSection;
  cJSON *current;
  struct rspSession *rsp;
  gint state;		/* 0=idle, 1=flushing, 2=load next, 3=next network, 4=discovering format, 5=buffering, 6=playing */
  char *msg;
  cJSON *meta;

  /* properties */
  gchar     *conf_file;
  gchar     *conf_json;
  gint      svr_timeout;
  gboolean  sendRaw;
  gboolean  loop;
  GstCaps   *caps;

};

struct _GstrspsrcClass {
  GstPushSrcClass parent_class;
};

GType gst_rspsrc_get_type(void);

G_END_DECLS


#endif /* __GST_rspsrc_H__ */
