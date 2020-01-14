/* GStreamer
 * Copyright (C) <2005> Wim Taymans <wim@fluendo.com>
 * Copyright (C) <2005> Nokia Corporation <kai.vehmanen@nokia.com>
 * Copyright (C) <2019> Ethan Funk <ethan@redmountainradio.com>
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

/**
 * SECTION:element-rspsink
 * @see_also: rspsrc
 *
 * rspsink is a network sink that encodes Resilient Streaming Protocol (RSP)
 * media streams to one (or more for clustered) RSP relay servers,
 * multicast groups, or a direct UDP port feed conforming to the RSP format.
 *
 * rspsink requires either the config-json property or the config-file property
 * to be set to configure the network interface for a desired RSP session.
 * Both properties take RSP session configuration data either directly as a jSON
 * string, or as a path to a file which contains the jSON formated RSP session
 * configuration.  See the RSP specification at http://redmountainradio.com/rsp
 * for RSP session configuration details.
 *
 * rspsink has several additional properties to control how it formats data
 * sent to network destinations:
 * 
 * 	"sendto" property [comma separated ip & port address list string], 
 * 	(default <empty list>) specifies a list of comma separated ip addresses,
 * 	in numberic format, to which packets are to be sent to. For IPv4 numeric addresses, 
 * 	the format is standard doted-quad with a required colon separated port number,
 * 	i.e. 127.0.0.1:5076. For IPv6 numeric, the format is a bracket enclosed, 
 * 	colon segmented, hexidecimal IPv6 address, with a trailing colon separated 
 * 	port number, i.e. [fe80::1ff:fe23:4567:890a]:5076.
 * 
 * 	"ttl" property [multicast TTL decimal integer], (default 20) specifies a multicast 
 * 	packet TTL value hop count limit.
 * 
 * 	"tos" property [integer], (default 0) specifies the type-of-service byte 
 * 	to be set for all outgoing packets.
 * 
 * 	"bindIP4" property [dotted-quad with colon trailed port interface bind address], 
 * 	(default <empty>, system assigned port) specifies the interface bind-to address 
 * 	for outgoing IPv4 packets, i.e. 192.168.1.5:5076.
 *
 * 	"bindIP6" property [bracket enclosed hexidecimal IPv6 address with colon trailed 
 * 	port interface bind address], (default <empty>, system assigned port) specifies the 
 * 	interface bind-to address for outgoing IPv6 packets, 
 * 	i.e. [fe80::1ff:fe23:4567:890a]:5076
 *  
 * 	"fec" property [2 through 127], (96 befaut) specifies how many network data 
 * 	packets out of every 255 carry Reed-Solomon forward error correction codes. 
 * 	The remaining packets (255 - FEC) will carry payload data. Using the defaut 
 * 	value of 96, allows 96 packets out of 255, or 37% of the packets to be lost 
 * 	in transit, on average (over an interleaver period), with out any loss of data.
 * 
 * 	"payload" property [16 through 256, in steps of 16], (default 128) specifies the 
 * 	length of the payload portion of a network packet, in bytes. This is one of
 * 	two controls that set the interleaver column size in bytes.
 *
 * 	"interleaving" property [1 through 85], (16 default) specifies an additional 
 * 	multiplication factor for the Payload property above to specify the interleaver 
 * 	column byte size in bytes.  For example, with the default 64 byte Payload size, 
 * 	an Interleave value of 4 would yield the column size of 256 bytes-> 4 network 
 * 	packets of 64 bytes sent per interleaver column.
 * 
 * 	"rs" property [yes/no], (default no) specifies if additional Reed-Soloman coding
 * 	is added to each network packet send. The packets size will be increase upward to
 * 	form a 256 bytes packet (or 258 byte packet for extended packets) with the extra 
 * 	bytes being RS checksums. This allows for the possibility of the receiver to correct
 * 	a damaged packet when data is sent over a medium with out UDP checksums.  Since 
 * 	networks using UDP packet checksums will throw out UDP packets that fail checksum
 * 	checks before they are be delivered to the recever application, no correction can
 * 	be made to a damaged packed on a UDP network using checksums, even if this option 
 * 	is set to "yes".
 * 
 * 	"crc" property [yes/no], (default no) specifies if network packets should have an extra
 * 	32 bit CRC appended to the packet.  This option is for use in a network where UDP packets
 * 	are not automatically check-summed by befault by the operating system's network stack.
 * 	For the protocol's reed-solomon forward error correction to work efficiently at the 
 * 	interleaver level, the protocol needs to be able to identify missing or back packets
 * 	that need to be repaired, and where they are in the data stream. UDP packets that have
 * 	been checksumed by the OS and arrive damaged, will fail the validity check on the receive 
 * 	side, and will simply be "missing," allowing the protocol to know where fixes need to be
 * 	made. RS error correction is twice as effective at reconstructing in missing data than 
 * 	it is at identifing bad data AND fixing it. So this option allows us to add our own CRC32
 * 	checksum to packets at the application level for currupt data identification, in case the 
 * 	OS isn't doing that for us already.
 * 
 * 	"keyFile" property [file path string] (default none) specifies a path in the file
 * 	system to an rsa private key to use for public-private key authentication of the stream
 * 	data.
 * 
 * 	"keyPassword" property [password string] (default none) specifies a password string
 * 	to be used with the specified PrivateKeyFile, if the private key was generated with additional
 * 	password protection.
 * 
 *!!!
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

#include "gstrspsink.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

GST_DEBUG_CATEGORY_STATIC(rspsink_debug);
#define GST_CAT_DEFAULT(rspsink_debug)

#define gst_rspsink_parent_class parent_class
G_DEFINE_TYPE (Gstrspsink, gst_rspsink, GST_TYPE_BASE_SINK);

#define RSP_DEFAULT_SENDTO				NULL
#define RSP_DEFAULT_TTL					20
#define RSP_DEFAULT_TOS					0
#define RSP_DEFAULT_BINDIP4			NULL
#define RSP_DEFAULT_BINDIP6			NULL
#define RSP_DEFAULT_FEC					96
#define RSP_DEFAULT_PAYLOAD			128
#define RSP_DEFAULT_INTERLEAVING		16
#define RSP_DEFAULT_CRC					0
#define RSP_DEFAULT_RS					0
#define RSP_DEFAULT_KEY_FILE			NULL
#define RSP_DEFAULT_KEY_PW				NULL

enum
{
	PROP_0,

	PROP_SENDTO,
	PROP_TTL,
	PROP_TOS,
	PROP_BINDIP4,
	PROP_BINDIP6,
	PROP_FEC,
	PROP_PAYLOAD,
	PROP_INTERLEAVING,
	PROP_CRC,
	PROP_RS,
	PROP_KEY_FILE,
	PROP_KEY_PW,

	PROP_LAST
};

static void gst_rspsink_finalize(GObject * object);
static GstFlowReturn gst_rspsink_render(GstBaseSink *sink, GstBuffer * buffer);
static gboolean gst_rspsink_event(GstBaseSink *sink, GstEvent *event);
static gboolean gst_rspsink_setcaps(GstBaseSink *sink, GstCaps *caps);
static gboolean gst_rspsink_start(GstBaseSink *sink);
static gboolean gst_rspsink_stop(GstBaseSink *sink);
static gboolean gst_rspsink_unlock(GstBaseSink *sink);
static void gst_rspsink_set_property(GObject *object, guint prop_id,
											const GValue *value, GParamSpec *pspec);
static void gst_rspsink_get_property(GObject *object, guint prop_id,
											GValue *value, GParamSpec *pspec);
											
gboolean rspsinkplugin_init(GstPlugin *plugin){
	if(!gst_element_register(plugin, "rspsink", GST_RANK_NONE,  GST_TYPE_rspsink))
		return FALSE;
	return TRUE;
}

GST_PLUGIN_DEFINE (
	GST_VERSION_MAJOR,
	GST_VERSION_MINOR,
	rspsink,
	"Send data via RSP protocol",
	rspsinkplugin_init,
	"0.8",
	"LGPL",
	PACKAGE_NAME,
	"http://redmountainradio.com/rsp"
)

static GstStaticPadTemplate sink_template = GST_STATIC_PAD_TEMPLATE("sink",
	GST_PAD_SINK,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS_ANY);

static void gst_rspsink_class_init(GstrspsinkClass *klass){
	GObjectClass *gobject_class;
	GstElementClass *gstelement_class;
	GstBaseSinkClass *gstbasesink_class;

	gobject_class = (GObjectClass *)klass;
	gstelement_class = (GstElementClass *)klass;
	gstbasesink_class = (GstBaseSinkClass *)klass;
	
	GST_DEBUG_CATEGORY_INIT(rspsink_debug, "rspsink", 0, "RSP stream sink");
	
	gobject_class->set_property = gst_rspsink_set_property;
	gobject_class->get_property = gst_rspsink_get_property;
	gobject_class->finalize = gst_rspsink_finalize;
	gstbasesink_class->event = gst_rspsink_event; // Handle TAGS
	gstbasesink_class->set_caps = gst_rspsink_setcaps;
	gstbasesink_class->render = gst_rspsink_render;
	gstbasesink_class->start = gst_rspsink_start;
	gstbasesink_class->stop = gst_rspsink_stop;
	gstbasesink_class->unlock = gst_rspsink_unlock;

	gst_element_class_add_pad_template(gstelement_class,
					gst_static_pad_template_get(&sink_template));

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_SENDTO,
		g_param_spec_string("sendto", "send to address:port list.",
			"A comma separated list of address:ports, or [address]:port for IPv6, in numberic format, to which packets are to be sent. Default empty.",
			RSP_DEFAULT_SENDTO, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_TTL,
		g_param_spec_int("ttl", "Multicast packet ttl value.",
			"Numerical value to set all sent multicast packet's ttl values to. Default 20.",
			0, G_MAXUINT8, RSP_DEFAULT_TTL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_TOS,
		g_param_spec_int("tos", "Packet tos value.",
			"Numerical value to set all sent packet's type-of-service values to. Default 0.",
			0, G_MAXUINT8, RSP_DEFAULT_TOS, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_BINDIP4,
		g_param_spec_string("bindip4", "Bind address:port for IPv4 packets.",
			"Interface address:port string with which to bind the sending socket for IPv4 packets. Default empty (none).",
			RSP_DEFAULT_BINDIP4, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_BINDIP6,
		g_param_spec_string("bindip6", "Bind [address]:port for IPv6 packets.",
			"Interface [address]:port string with which to bind the sending socket for IPv6 packets. Default empty (none).",
			RSP_DEFAULT_BINDIP6, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_FEC,
		g_param_spec_int("fec", "Forward error correction redundancy level.",
			"How many network data packets, out of every 255, will carry Reed-Solomon forward error correction codes. Default 96",
			2, 127, RSP_DEFAULT_FEC, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_PAYLOAD,
		g_param_spec_int("payload", "Network packet payload size in bytes.",
			"Network packet payload size in bytes, 16 through 256 in 16 byte steps. Default 128.",
			16, 256, RSP_DEFAULT_PAYLOAD, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_INTERLEAVING,
		g_param_spec_int("interleaving", "Additional interleaving factor.",
			"Specifies a multiplication factor, N, to increase data interleaving: (N x the Payload) by 255. Default 16.",
			1, 85, RSP_DEFAULT_INTERLEAVING, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property (gobject_class, PROP_CRC,
	g_param_spec_boolean ("crc", "Shall an additional CRC code be added to packets?",
		"Speciciesif a CRC code should be added to the packet before transmission to support transport of raw packet data over non-IP protocols. Default no.",
		RSP_DEFAULT_CRC, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_RS,
	g_param_spec_boolean ("rs", "Shall additional FEC coding be added to packets?",
		"Speciciesif if additional FEC coding is added to the packet before transmission to support transport of raw packet data over non-IP protocols. Setting to yes, will cause packet data to be filled out from the specified payload size to 255 bytes with extra Reed-Solomon FEC codes. Default no.",
		RSP_DEFAULT_RS, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_KEY_FILE,
		g_param_spec_string("keyFile", "Stream authentication private key file path.",
			"Specifies a path in the file system to an RSA private key to use for public-private key authentication of the transmitted stream data. See RSP specification for details. Default none, authentication disabled.",
			RSP_DEFAULT_KEY_FILE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	g_object_class_install_property(G_OBJECT_CLASS(klass), PROP_KEY_PW,
		g_param_spec_string("keyPassword", "Stream authentication password for the specified key file.",
			"If the private key file requires a password string, this is how you specify it. Default none.",
			RSP_DEFAULT_KEY_PW, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS)
	);

	gst_element_class_set_static_metadata(gstelement_class,
		"RSP packet transmitter", "Sink/Network",
		"Transmit streaming data over a network via RSP protocol - http://redmountainradio.com/rsp",
		"Ethan Funk <ethan@redmountainradio.com>");
}

static void gst_rspsink_init(Gstrspsink *rspsink){
	rspsink->destinations = NULL;
	rspsink->rsp = rspSessionNew("gstrspsink/0.8");
	rspsink->rsp->referenceDesignator = (void*)rspsink;
	
	rspsink->frag_offset = 0;
	rspsink->curMetaStr = NULL;
	rspsink->metaPos = 0;

	rspsink->prop_sendto = RSP_DEFAULT_SENDTO;
	rspsink->prop_ttl = RSP_DEFAULT_TTL;
	rspsink->prop_tos = RSP_DEFAULT_TOS;
	rspsink->prop_bindip4 = RSP_DEFAULT_BINDIP4;
	rspsink->prop_bindip6 = RSP_DEFAULT_BINDIP6;
	rspsink->prop_fec = RSP_DEFAULT_FEC;
	rspsink->prop_payload = RSP_DEFAULT_PAYLOAD;
	rspsink->prop_interleaving = RSP_DEFAULT_INTERLEAVING;
	rspsink->prop_crc = RSP_DEFAULT_CRC;
	rspsink->prop_rs = RSP_DEFAULT_RS;
	rspsink->prop_key_file = RSP_DEFAULT_KEY_FILE;
	rspsink->prop_key_pw = RSP_DEFAULT_KEY_PW;
}

gchar *gvalToString(GValue *val){
	gchar *str;
	if(G_VALUE_HOLDS_STRING(val))
		str = g_value_dup_string(val);
	else
		str = gst_value_serialize(val);
	return str;
}

void appendTagData(const GstTagList *tags, const gchar *tag, gpointer user_data){
	cJSON *obj = (cJSON *)user_data;
	cJSON *ar;
	GValue val = { 0, };
	gchar *str;
	const char *prop;
	double num;

	gst_tag_list_copy_value(&val, tags, tag);
	prop = gst_tag_get_nick(tag);

	str = NULL;
	if(!strcmp(prop, GST_TAG_EXTENDED_COMMENT)){
		// special AR specific data
		str = gvalToString(&val);
		if(strstr(str, "AR=") == str){
			if(ar = cJSON_Parse(str+3))
				cJSON_AddItemToObject(obj, "AR", ar);
		}else{
			g_free(str);
			str = NULL;
		}
	}else if(!strcmp(prop, GST_TAG_TITLE)){
		str = gvalToString(&val);
		cJSON_AddStringToObject(obj, "Name", str);
	}else if(!strcmp(prop, GST_TAG_ARTIST)){
		str = gvalToString(&val);
		cJSON_AddStringToObject(obj, "Artist", str);
	}else if(!strcmp(prop, GST_TAG_ALBUM)){
		str = gvalToString(&val);
		cJSON_AddStringToObject(obj, "Album", str);
	}else if(!strcmp(prop, GST_TAG_TRACK_NUMBER)){
		str = gvalToString(&val);
		num = g_value_get_uint(&val);
		cJSON_AddNumberToObject(obj, "Track", num);
	}else if(!strcmp(prop, GST_TAG_ALBUM_ARTIST)){
		str = gvalToString(&val);
		cJSON_AddStringToObject(obj, "AlbumArtist", str);
	}else if(!strcmp(prop, GST_TAG_ISRC)){
		str = gvalToString(&val);
		cJSON_AddStringToObject(obj, "ISRC", str);
	}
	if(str)
		g_free(str);	

	g_value_unset(&val);
}

void queueTagsToRSP(const GstTagList *tags, struct rspSession *rsp){
	cJSON *obj, *root;
	
	root = cJSON_CreateObject();
	obj = cJSON_CreateObject();
	gst_tag_list_foreach(tags, appendTagData, obj);
	cJSON_AddItemToObject(root, "item", obj);
	rspSessionQueueMetadata(rsp, root, NULL);
}

static gboolean gst_rspsink_event(GstBaseSink *sink, GstEvent *event){
	Gstrspsink *rspsink = GST_rspsink(sink);
	GstTagList *list;

	switch(GST_EVENT_TYPE(event)){
		case GST_EVENT_TAG:
			gst_event_parse_tag(event, &list);
			queueTagsToRSP(list, rspsink->rsp);
			break;
			
		default:
			if(GST_BASE_SINK_CLASS(parent_class)->event){
				event = gst_event_ref(event);
				return GST_BASE_SINK_CLASS(parent_class)->event(sink, event);
			}
			break;
	}
	return TRUE;
}

static gboolean gst_rspsink_setcaps(GstBaseSink *sink, GstCaps *caps){
	Gstrspsink *rspsink = GST_rspsink(sink);
	GstStructure *capstruct;
	const GValue *val;
	GType type;
	const gchar *key;
	unsigned int i, num;
	unsigned int mIDVal;
	cJSON *obj, *root;
	
	root = cJSON_CreateObject();
	obj = cJSON_CreateObject();
	
	capstruct = gst_caps_get_structure(caps, 0);
	num = gst_structure_n_fields(capstruct);
	cJSON_AddStringToObject(obj, "Type", gst_structure_get_name(capstruct));
	for(i=0; i<num; i++){
		key = gst_structure_nth_field_name(capstruct, i);
		val = gst_structure_get_value(capstruct, key);
		type = G_VALUE_TYPE(val);
		if(G_VALUE_HOLDS_STRING(val))
			cJSON_AddStringToObject(obj, key, g_value_get_string (val));
		else if(g_value_type_transformable(type, G_TYPE_DOUBLE)){
			GValue dval = G_VALUE_INIT;
			g_value_init (&dval, G_TYPE_DOUBLE);
			g_value_transform(val, &dval);
			cJSON_AddNumberToObject(obj, key, g_value_get_double(&dval));
		}
	}
	srand(time(NULL));
	while(!(mIDVal = ((unsigned int)rand() & 0xffffffff)));
	cJSON_AddNumberToObject(obj, "mID", mIDVal);
	// and queue it for RSP transmission
	cJSON_AddItemToObject(root, "Content", obj);
	rspSessionQueueMetadata(rspsink->rsp, root, NULL);
	
	return TRUE;
}


static GstFlowReturn gst_rspsink_render(GstBaseSink *sink, GstBuffer *buffer){
	Gstrspsink *rspsink = GST_rspsink(sink);
	GstMapInfo info;
	char *tmp_ptr;
	unsigned char *packetPtr;
	unsigned char dataFrameSize;
	unsigned int n, size;
	struct destination *dest_ptr;
	
	if(gst_buffer_map(buffer, &info, GST_MAP_READ)){
		tmp_ptr = info.data;
		n = info.size;
		while(n > 0){
			// NOTE: First byte of frame is meta data, followed by payload data
			dataFrameSize = 255 - rspsink->rsp->FECroots - 1;
			if(n < (signed int)(dataFrameSize - rspsink->frag_offset)){	// note 1 extra byte reserved for meta data stream
				// less than a full RSP row frame, save fragment for next time render is called
				memcpy(rspsink->dataFrame + rspsink->frag_offset + 1, tmp_ptr, n);
				rspsink->frag_offset = rspsink->frag_offset + n;
				n = 0;
			}else{
				// enough to fill a frame
				size = dataFrameSize - rspsink->frag_offset;					// note 1 extra byte reserved for meta data stream
				memcpy(rspsink->dataFrame + rspsink->frag_offset + 1, tmp_ptr, size);
				rspsink->frag_offset = 0;
				n = n - size;
				tmp_ptr = tmp_ptr + size;
				
				if(rspsink->curMetaStr == NULL){
					// check to see if there is new metadata to start adding to frames
					if(rspsink->curMetaStr = rspSessionNextMetaStr(rspsink->rsp))
						rspsink->metaPos = 0;
				}
				// set next metadata byte, if any
				if(rspsink->curMetaStr){
					if((rspsink->dataFrame[0] = rspsink->curMetaStr[(rspsink->metaPos)++]) == 0){
						// end of string
						free(rspsink->curMetaStr);
						rspsink->curMetaStr = NULL;
					}
				}else
					// No metadata: set metadata byte in packet to NULL char
					rspsink->dataFrame[0] = 0; 
				
				// we have a full frame... process through data RS encoder and write to interleaver row
				if(!rspSessionWriteData(rspsink->rsp, rspsink->dataFrame, dataFrameSize + 1)){
					// no error... check for packets comming out of interleaver to send
					while(size = rspSessionReadPacket(rspsink->rsp, &packetPtr, NULL)){
						// travers the destinations linked list, sending the packet to each destination.
						if(dest_ptr = rspsink->destinations){
							int i = 0;
							do{

//		if((packetPtr[0] & 0x03) == RSP_FLAG_EXT)
//			fprintf(stderr, "%d:blk=%d,col=%d,fec=%d,il=%d\n", i, packetPtr[3], packetPtr[4], packetPtr[1], packetPtr[2]);
//		else
//			fprintf(stderr, "%d:blk=%d,col=%d\n", i, packetPtr[1], packetPtr[2]);

								rspSendto(dest_ptr->socket, packetPtr, size, 0, (struct sockaddr*)&dest_ptr->sock_addr);
								i++;
							}while(dest_ptr = dest_ptr->next);
						}
					}
				}
			}
		}
		
		gst_buffer_unmap(buffer, &info);
		return GST_FLOW_OK;
	}
	gst_buffer_unmap(buffer, &info);
	return GST_FLOW_ERROR;
}

void clients_clear(Gstrspsink *rspsink){
	struct destination *this, *client;
	
	if(rspsink->rsp_socket4 > -1){
		close(rspsink->rsp_socket4);
		rspsink->rsp_socket4 = -1;
	}
	if(rspsink->rsp_socket6 > -1){
		close(rspsink->rsp_socket6);
		rspsink->rsp_socket6 = -1;
	}
	client = rspsink->destinations;
	while(client){
		this = client;
		client = client->next;
		free(this);
	}
	rspsink->destinations = NULL;
}

struct sockaddr_in6 *setSockAddr(struct sockaddr_in6 *adrPtr, unsigned char ip6, unsigned char resolve, char *addrin){
	unsigned int size;
	struct sockaddr_in *v4bindAddr;
	char *pstr, *addr;
	unsigned short port;
	
	// TODO: use resolve as a DNS lookup enable flag.  No DNS resolve implemented yet.
	
	// separe address from port
	pstr = NULL;
	if(addr = strchr(addrin, '[')){
		// If IPv6 address is bracket enclosed, must be a number
		addr++;
		if(pstr = strchr(addr, ']')){
			*pstr = 0;
			pstr++;
			if(pstr = strchr(pstr, ':'))
				pstr++;
		}else
			return NULL;
	}else{
		// If address is NOT bracket enclosed, must be a name, an IPv4 doted quad address
		addr = addrin;
		if(pstr = strchr(addr, ':')){
			*pstr = 0; // null terminate the address portion
			pstr++;
		}
	}
	port = 0;
	if(pstr)
		port = atoi(pstr);
	if(!port)
		return NULL;

	size = sizeof(struct sockaddr_in6);
	bzero(adrPtr, size);
	if(ip6){
		// IPv6 network settings
#ifndef __linux__
		adrPtr->sin6_len = sizeof(struct sockaddr_in6);
#endif		
		if(inet_pton(AF_INET6, addr, &adrPtr->sin6_addr) <= 0)
			return NULL;
		adrPtr->sin6_family = AF_INET6;
		adrPtr->sin6_port = htons(port);
	}else{
		v4bindAddr = (struct sockaddr_in *)adrPtr;
#ifndef __linux__
		v4bindAddr->sin_len = sizeof(struct sockaddr_in);
#endif		
		if(inet_pton(AF_INET, addr, &v4bindAddr->sin_addr.s_addr) <= 0)
			return NULL;
		v4bindAddr->sin_family = AF_INET;
		v4bindAddr->sin_port = htons(port);
	}
	return adrPtr;
}

int socketSetup(Gstrspsink *rspsink, unsigned char ip6){
	int sd;
	unsigned int size;
	struct sockaddr_in6 bindAddr;
	int trueVal = 1;
	
	sd = -1;
	if(ip6){
		if((sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0)
			return -1;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(trueVal));
		// set the multicast TTL value for the multicast hop threshold, in case any destination are multicast
		if(setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (unsigned char *)&rspsink->prop_ttl, sizeof(rspsink->prop_ttl)) < 0){
			goto fail;
		}
		if(rspsink->prop_bindip6){
			if(setSockAddr(&bindAddr, TRUE, FALSE, rspsink->prop_bindip6) == NULL)
				goto fail;
			size = sizeof(struct sockaddr_in6);
			if(bind(sd, (struct sockaddr *)&bindAddr, size) < 0)
				goto fail;
		}
	}else{
		// use old (IPv4) network settings
		if((sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
			return -1;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(trueVal));
		// set the multicast TTL value for the multicast hop threshold, in case any destination are multicast
		if(setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, (unsigned char *)&rspsink->prop_ttl, sizeof(rspsink->prop_ttl)) < 0){
			goto fail;
		}
		// bint to port, if set
		if(rspsink->prop_bindip4){
			if(setSockAddr(&bindAddr, FALSE, FALSE, rspsink->prop_bindip4) == NULL)
				goto fail;
			size = sizeof(struct sockaddr_in);
			if(bind(sd, (struct sockaddr *)&bindAddr, size) < 0)
				goto fail;
		}
	}
	if(rspsink->prop_tos){
		// this might not work for IPv6 sockets, so I commented out the failure.
		int dsval = dsval & 0xFB;  // upper six bits only are valid
		setsockopt(sd, IPPROTO_IP, IP_TOS, &dsval, sizeof(dsval));		
//		if(setsockopt(sd, IPPROTO_IP, IP_TOS, &dsval, sizeof(dsval)) < 0)
//			goto fail;
	}
	return sd;
	
fail:
	if(sd >= 0)
		close(sd);
	return -1;
}

struct destination *client_add(Gstrspsink *rspsink, const gchar *host){
	struct destination *client;
	struct sockaddr_in6 sockaddr;
	gchar *tmp;

	tmp = g_strdup(host);
	if(!setSockAddr(&sockaddr, TRUE, TRUE, tmp)){
		g_free(tmp);
		tmp = g_strdup(host);
		if(!setSockAddr(&sockaddr, FALSE, TRUE, host)){
			GST_ELEMENT_WARNING(rspsink, RESOURCE, WRITE,
							("Failed to resolve client address %s", host),
							("Failed to resolve client address %s", host));
			g_free(tmp);
			return NULL;
		}
	}
	g_free(tmp);
	
	if(client = (struct destination *)calloc(1, sizeof(struct destination))){
		if(sockaddr.sin6_family == AF_INET6){
			if(rspsink->rsp_socket6 < 0){
				// create socket
				rspsink->rsp_socket6 = socketSetup(rspsink, 1);
				if(rspsink->rsp_socket6 < 0){
					GST_ERROR_OBJECT(rspsink, "Failed to create IPv6 socket");
					goto cleanup;
				}
			}
			client->socket = rspsink->rsp_socket6;
			// populate socket sendto address
			client->sock_addr = sockaddr;
		}else if(sockaddr.sin6_family == AF_INET){
			if(rspsink->rsp_socket4 < 0){
				// create socket
				rspsink->rsp_socket4 = socketSetup(rspsink, 0);
				if(rspsink->rsp_socket4 < 0){
					GST_ERROR_OBJECT(rspsink, "Failed to create IPv4 socket");
					goto cleanup;
				}
			}
			client->socket = rspsink->rsp_socket4;
			// populate native socket sendto address
			client->sock_addr = sockaddr;
		}else{
			// invalid socket family type
			goto cleanup;
		}
		client->next = rspsink->destinations;
		rspsink->destinations = client;
		return client;
	}

cleanup:
	if(client)
		free(client);
	return NULL;
}

static void gst_rspsink_finalize(GObject *object){
	Gstrspsink *rspsink = GST_rspsink(object);

	if(rspsink->curMetaStr)
		free(rspsink->curMetaStr);
	if(rspsink->prop_sendto)
		free(rspsink->prop_sendto);
	if(rspsink->prop_bindip4)
		free(rspsink->prop_bindip4);
	if(rspsink->prop_bindip6)
		free(rspsink->prop_bindip6);
	if(rspsink->prop_key_file)
		free(rspsink->prop_key_file);
	if(rspsink->prop_key_pw)
		free(rspsink->prop_key_pw);
	
	rspSessionFree(rspsink->rsp);
	
	clients_clear(rspsink);
		
	G_OBJECT_CLASS(rspsink)->finalize(object);
}

static gboolean gst_rspsink_start(GstBaseSink *sink){
	Gstrspsink *rspsink = GST_rspsink(sink);
	gchar **clients;
	gint i;

	if(rspsink->prop_sendto == NULL){
		GST_ERROR_OBJECT(rspsink, "Failed: sendto destination property is empty.");
		return FALSE;
	}
	
	rspSessionClear(rspsink->rsp, TRUE);
	
	rspsink->rsp->FECroots = rspsink->prop_fec;
	rspsink->rsp->interleaving = rspsink->prop_interleaving;
	rspsink->rsp->colSize = rspsink->prop_payload;
	rspsink->rsp->flags = 0;
	if(rspsink->prop_crc)
		rspsink->rsp->flags = rspsink->rsp->flags | RSP_FLAG_CRC;
	if(rspsink->prop_rs)
		rspsink->rsp->flags = rspsink->rsp->flags | RSP_FLAG_RS;
	
	if(rspSessionInit(rspsink->rsp) != RSP_ERROR_NONE){
		GST_ERROR_OBJECT(rspsink, "Failed to initialize RSP session. Verify settings.");
		return FALSE;
	}

  /* clear all existing clients */
	clients_clear(rspsink);
	
	/* rebuild client list based on current prop_sendto string */
	clients = g_strsplit(rspsink->prop_sendto, ",", 0);
	for(i = 0; clients[i]; i++)
		client_add(rspsink, clients[i]);
	g_strfreev(clients);
	if(rspsink->destinations)
		return TRUE;
	GST_ERROR_OBJECT(rspsink, "Failed to specifiy at least one VALID network destination.");
	return FALSE;
}

static gboolean gst_rspsink_stop(GstBaseSink *sink){
	Gstrspsink *rspsink = GST_rspsink(sink);

	gst_rspsink_unlock(sink);
	rspSessionClear(rspsink->rsp, TRUE);
	
	return TRUE;
}

static gboolean gst_rspsink_unlock(GstBaseSink *sink){
	Gstrspsink *rspsink = GST_rspsink(sink);
	
	clients_clear(rspsink);
	
	return TRUE;
}

static void gst_rspsink_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec){
	Gstrspsink *rspsink = GST_rspsink(object);

	switch(prop_id){
		case PROP_SENDTO:
			if(rspsink->prop_sendto)
				free(rspsink->prop_sendto);
			rspsink->prop_sendto = g_value_dup_string(value);
			break;

		case PROP_TTL:
			rspsink->prop_ttl = g_value_get_int(value);
			break;

		case PROP_TOS:
			rspsink->prop_tos = g_value_get_int(value);
			break;

		case PROP_BINDIP4:
			if(rspsink->prop_bindip4)
				free(rspsink->prop_bindip4);
			rspsink->prop_bindip4 = g_value_dup_string(value);
			break;

		case PROP_BINDIP6:
			if(rspsink->prop_bindip6)
				free(rspsink->prop_bindip6);
			rspsink->prop_bindip6 = g_value_dup_string(value);
			break;

		case PROP_FEC:
			rspsink->prop_fec = g_value_get_int(value);
			break;

		case PROP_PAYLOAD:
			rspsink->prop_payload = g_value_get_int(value);
			break;

		case PROP_INTERLEAVING:
			rspsink->prop_interleaving = g_value_get_int(value);
			break;

		case PROP_CRC:
			rspsink->prop_crc = g_value_get_boolean(value);
			break;

		case PROP_RS:
			rspsink->prop_rs = g_value_get_boolean(value);
			break;

		case PROP_KEY_FILE:
			if(rspsink->prop_key_file)
				free(rspsink->prop_key_file);
			rspsink->prop_key_file = g_value_dup_string(value);
			break;

		case PROP_KEY_PW:
			if(rspsink->prop_key_pw)
				free(rspsink->prop_key_pw);
			rspsink->prop_key_pw = g_value_dup_string(value);
			break;

		default:
			break;
	}
}

static void gst_rspsink_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec){
	Gstrspsink *rspsink = GST_rspsink(object);
	
	switch(prop_id){
		case PROP_SENDTO:
			g_value_set_string(value, rspsink->prop_sendto);
			break;

		case PROP_TTL:
			g_value_set_int(value, rspsink->prop_ttl);
			break;

		case PROP_TOS:
			g_value_set_int(value, rspsink->prop_tos);
			break;

		case PROP_BINDIP4:
			g_value_set_string(value, rspsink->prop_bindip4);
			break;

		case PROP_BINDIP6:
			g_value_set_string(value, rspsink->prop_bindip6);
			break;

		case PROP_FEC:
			g_value_set_int(value, rspsink->prop_fec);
			break;

		case PROP_PAYLOAD:
			rspsink->prop_payload = g_value_get_int(value);
			break;

		case PROP_INTERLEAVING:
			g_value_set_int(value, rspsink->prop_interleaving);
			break;

		case PROP_CRC:
			g_value_set_boolean(value, rspsink->prop_crc);
			break;

		case PROP_RS:
			g_value_set_boolean(value, rspsink->prop_rs);
			break;

		case PROP_KEY_FILE:
			g_value_set_string(value, rspsink->prop_key_file);
			break;

		case PROP_KEY_PW:
			g_value_set_string(value, rspsink->prop_key_pw);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}


