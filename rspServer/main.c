/*
 
 Copyright (c) 2011-2015 Ethan Funk
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
 documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
 the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
 and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies or substantial portions 
 of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
 TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
 CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 DEALINGS IN THE SOFTWARE.
 
*/

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <pthread.h>
#include <math.h>
#include <sys/un.h>
#include <unistd.h>
#include <grp.h>
#include "rs.h"
#include "rsp.h"

#define clientID "rspServer/1.6"

#ifdef __APPLE__
	#define YIELD() pthread_yield_np()
	#include <malloc/malloc.h>
#else
	#define YIELD() pthread_yield()
#endif

struct listenerNode {
	unsigned int		UID;		// Unique ID number for listener record
	unsigned int		hash;		// An ELF string hash created from the apparentAddress and rr (below) via string, if set
	struct recvrRecord	rr;
	time_t				joined;
	unsigned char		keep;
	unsigned char		authBlock;
	int					socket;		// used for multicast rsp or for shoutcast tcp
	unsigned char		relayType;	// 0 = rsp, 1 = shoutcast
	int					offset;		// shoutcast bytecount since meta send. -1 indicates no metadata requested
	unsigned int		pr_Idx;		// shoutast listener: ending index of last sent byte of proroll buffer
	unsigned char		pr_curBlk;		// RSP listener: current proroll Block - moves forward until = endBlk
	unsigned char		pr_curCol;		// RSP listener: current proroll Column - moves forward until = endCol
	unsigned char		pr_endBlk;		// RSP listener: ending proroll Block
	unsigned char		pr_endCol;		// RSP listener: ending proroll Column
	char				*mptr;		// shoutcast last sent meta data string.
	pthread_mutex_t		lock;
	struct listenerNode	*link;		// next listener in list, or NULL
};

struct sourceRecord {
	struct sourceRecord *next;
	pthread_mutex_t	lock;
	char *sourceName;
	struct rspSession *rsp;
	struct rspSession *recode_rsp;
	int tc_socket;
	unsigned char *retry_data;
	unsigned int retry_size;
	unsigned int rspfrag;
	unsigned char reformFrame[255];
	unsigned char *sc_prerollBuf;
	unsigned int sc_prerollIdx;
	unsigned int sc_prerollSize;
	unsigned int sc_prerollFill;

	unsigned short prerollPace;
	
	cJSON *source_conf;				// sub-item of the master configuration, do not detached or free
	cJSON *rspStream;				// This WILL be freed:  If it is a sub-item of the master configuration,
									// make sure to create a reference to the item.  Don't use the original.
	cJSON *rsp_conf;				// sub-item of source_conf, do not detached or free
	cJSON *sc_conf;					// sub-item of source_conf, do not detached or free
	cJSON *meta_exclude;			// sub-item of source_conf, do not detached or free
	cJSON *trackList;
	pthread_mutex_t	trackLock;
	pthread_t source_relay_thread;
	unsigned short listener_peak;
	unsigned short listener_count;
	float relay_count;
	struct listenerNode	*listHead;
	time_t sc_lastreport;
	unsigned short relay_limit;
	unsigned short sc_underrun_limit;
	unsigned char sourceStatus;
	pid_t child;
	unsigned char authBlock;
	unsigned char run;
};

struct serverContext {
	cJSON *root_conf;
	char* conf_file;
	int ns_socket;
	int svr_socket4;
	int svr_socket6;
	int sc_socket4;
	int sc_socket6;
	pthread_mutex_t	lock;
	struct	sockaddr_in6 forwardAddress;
	pthread_t reportV4_thread;
	pthread_t reportV6_thread;
	pthread_t scListen4_thread;
	pthread_t scListen6_thread;
	struct rspSession *rep_rsp;
	unsigned int relay_timeout;
	unsigned int sc_metaperiod;
	unsigned int sc_sock_timeout;
	unsigned int sc_reportperiod;
	char *relay_identity;
	char *sc_identity;
	char *sc_default;
	struct listenerNode	*listHead;		// listener report linked list for reports not associated with sources we are relaying
	struct sourceRecord *sourceList;	// array of sources we are relaying, each record contains it's own listHead (as above)
	unsigned char run;
	unsigned char log_listeners;		// set true if new listener added and old listeners removed should be logged
	unsigned int lastUID;
	pthread_mutex_t	uid_lock;
};

// single global variable (serverContext structure) instance used by this process.
struct serverContext context;

// empty string: useful for shoutcast metadata pading
static unsigned char empty[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

struct threadPass {
	int sock;
	int *sockPtr;
	struct serverContext *cPtr;
	struct sockaddr_in6 addr;
};

struct relayPass {
	struct serverContext *cPtr;
	struct sourceRecord *sPtr;
};


// struct rspSession *debugSession;

// Some handy untility functions for manipulating strings, URLs, comparing cjSON objects, hashing, etc.

void appendbytes(char **data, unsigned int *length, char *frag, unsigned int size)
{
	unsigned int total;
	
	if(frag == NULL)
		return;
	if(*data == NULL)
		*data = calloc(1, size);
	total = *length + size;
	*data = realloc(*data, total);
	memcpy(*data+*length, frag, size);
	*length = total;
}

void replaceChar(char replace, char with, char* string)
{
	while(string = strchr(string, replace))
		*string = with;
}

char ctohex(char code) 
{
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

char *decodeURI(const char *in_uri)
{
	// returns a string pointer (that you must then free) containing a % decoded URI.
	char *out_uri, *loc;
	char valstr[3];
	
	out_uri = NULL;
	if(in_uri && (out_uri = (char *)malloc(strlen(in_uri)+1))){
		strcpy(out_uri, in_uri);
		loc = out_uri;
		while((loc = strchr(loc, '%')) && (strlen(loc) > 2)){
			strncpy(valstr, loc+1, 2);
			if(*loc = (char)strtoul(valstr, NULL, 16)){
				loc = loc + 1;
				memmove(loc, loc+2, strlen(loc+2));
			}else
				memmove(loc, loc+3, strlen(loc+3));
		}
	}
	return out_uri;
}

char *encodeURI(const char *in_uri)
{
	// returns a string pointer (that you must then free) containing a % encoded URI.
	char *out_uri, *outPtr;

	out_uri = NULL;
	if(in_uri && (out_uri = (char *)malloc((strlen(in_uri) * 3) + 1))){
		outPtr = out_uri;
		while(*in_uri){
			if(isalnum(*in_uri) || *in_uri == '-' || *in_uri == '_' || *in_uri == '.' || *in_uri == '~') 
				*outPtr++ = *in_uri;
			else{
				*outPtr++ = '%';
				*outPtr++ = ctohex(*in_uri >> 4);
				*outPtr++ = ctohex(*in_uri & 0x0f);
			}
			in_uri++;
		}
		*outPtr = 0;
	}
	return out_uri;
}

unsigned char compareItems(cJSON *A, cJSON *B, const char* const * obj_match)
{
	cJSON *itemA, *itemB;
	unsigned int type;
	const char* const *list;
	
	if((A == NULL) && (B == NULL))
		return TRUE;
	if((A == NULL) || (B == NULL) || ((type = (A->type & 0x00FF)) != (B->type & 0x00FF)))
		return FALSE;
	
	if((type == cJSON_Number) && (A->valuedouble != B->valuedouble))
		return FALSE;
	
	if((type == cJSON_String) && ((A->valuestring == NULL) || (B->valuestring == NULL) || strcmp(A->valuestring, B->valuestring)))
		return FALSE;
	
	if(type == cJSON_Array){
		if(cJSON_GetArraySize(A) != cJSON_GetArraySize(B))
			return FALSE;
		// look through each item in A and B, in order, to see if they match...
		itemA = A->child;
		itemB = B->child;
		while(itemA && itemB){
			if(!compareItems(itemA, itemB, NULL))
				return FALSE;
			itemA=itemA->next;			
			itemB=itemB->next;			
		}
	}
	if(type == cJSON_Object){
		if((obj_match == NULL) && (cJSON_GetArraySize(A) != cJSON_GetArraySize(B)))
			return FALSE;
		// look through each item in A...
		itemA = A->child;
		while(itemA){
			if(itemA->string == NULL)
				return FALSE;
			if(obj_match){
				// check if this is a property we are checking
				list = obj_match;
				while(*list){
					if(!strcmp(itemA->string, *list)){
						break;
					}
					list++;
				}
				if(*list == NULL){
					// not in list, skip!
					itemA=itemA->next;	
					continue;
				}
			}
			// for a matching item in B... order does not matter.
			if((itemB = cJSON_GetObjectItem(B, itemA->string)) == NULL)
				return FALSE;
			if(!compareItems(itemA, itemB, NULL))
				return FALSE;
			itemA=itemA->next;			
		}
		if(obj_match){			
			itemB = B->child;
			while(itemB){
				if(itemB->string == NULL)
					return FALSE;
				// check if this is a property we are checking
				list = obj_match;
				while(*list){
					if(!strcmp(itemB->string, *list)){
						break;
					}
					list++;
				}
				if(*list == NULL){
					// not in list, skip!
					itemB=itemB->next;	
					continue;
				}
				// for a matching item in A... order does not matter.
				if((itemA = cJSON_GetObjectItem(A, itemB->string)) == NULL)
					return FALSE;
				if(!compareItems(itemA, itemB, NULL))
					return FALSE;
				itemB=itemB->next;			
			}
		}
	}
	return TRUE;
}

int findMatchingItemInArray(cJSON *item, cJSON *inSet, char *key)
{
	// returns the index of an entry in array inSet that matches the item, or if key is set, returns the index
	// of the item in array inSet which itself contains a matching key value to the key value contained in item. 
	// returns -1 if item is NOT found in array inSet, or inSet and/or item is NULL
	// inset must be an cJSON array or NULL
	
	cJSON *entry, *itemVal, *setVal;
	int	index;
	
	// compare preset unicast relay destinations
	if((item == NULL) || (inSet == NULL))
		return -1;
	
	itemVal = NULL;
	if(key)
		itemVal = cJSON_GetObjectItem(item, key);
	index = -1;
	entry = inSet->child;
	while(entry){
		index++;
		if(itemVal){
			setVal = cJSON_GetObjectItem(entry, key);
			if(compareItems(itemVal, setVal, NULL))
				// match found
				return index;
		}else{
			if(compareItems(item, entry, NULL))
				// match found
				return index;
		}
		entry=entry->next;
	}
	// reached the end of inSet with no match
	return -1;		
}

// Now we get to the functions which this server is built on

ssize_t contextSendTo(struct serverContext *cPtr, const void *data, size_t size, struct sockaddr *dest)
{
	if(dest->sa_family == AF_INET6)
		return rspSendto(cPtr->svr_socket6, data, size, 0, dest);
	else if(dest->sa_family == AF_INET)
		return rspSendto(cPtr->svr_socket4, data, size, 0, dest);
	else
		return -1;
}

struct listenerNode *newListenerNode(struct serverContext *cPtr, struct recvrRecord *RR)
{
	// allocates a new record and sets it's structure to the RR record passed, but does not link it to a list.
	struct listenerNode *node;
	
	node = (struct listenerNode *)calloc(1, sizeof(struct listenerNode));
	node->link = NULL;
	pthread_mutex_lock(&cPtr->uid_lock); 
	// lower 8 bits of UID is process ID, increment bit 9.
	cPtr->lastUID = cPtr->lastUID + 256;
	node->UID = cPtr->lastUID;
	pthread_mutex_unlock(&cPtr->uid_lock); 
	
	if(RR){
		node->rr = *RR;
		if(node->rr.via){
			// use stated address and via
			node->hash = ELFHash(0, (char *)&(node->rr.statedAddress), sizeof(struct sockaddr_in6));
			node->hash = ELFHash(node->hash, node->rr.via, strlen(node->rr.via));
		}else
			// use apparent address
			node->hash = ELFHash(0, (char *)&(node->rr.apparentAddress), sizeof(struct sockaddr_in6));
		node->keep = FALSE;
	}else{
		node->hash = 0L;
		node->keep = TRUE;
	}
	node->relayType = 0;
	node->offset = -1;
	node->mptr = NULL;
	node->joined = time(NULL);
	node->socket = -1;
	pthread_mutex_init(&node->lock, NULL);
	return node;	
}

void freeListenerNode(struct listenerNode *node, unsigned char log)
{
	char *str;

	// assumes the node is already unlinked, and the lock is not helded
	pthread_mutex_destroy(&node->lock);
	
	if(log && node->rr.meta && (str = cJSON_PrintUnformatted(node->rr.meta))){
		syslog(LOG_INFO, "drop listener [UID=%u, Time=%lu, info=%s]", node->UID, (long unsigned int)difftime(time(NULL), node->joined), str);
		free(str);
	}
	
	rspRecvrReportFree(&node->rr);	
	if(node->socket > -1){
		shutdown(node->socket, SHUT_RDWR);
		close(node->socket);
	}
	free(node);
}

struct listenerNode	*unlinkNode(struct listenerNode *node, struct listenerNode *head, unsigned int uid) 
{ 
	struct listenerNode	*prev, *current; 	
	
	prev = head;
	
	pthread_mutex_lock(&prev->lock); 
	while((current = prev->link) != NULL){ 
		pthread_mutex_lock(&current->lock); 
		if((!uid && (current == node)) || (uid && (current->UID == uid))){ 
			prev->link = current->link;
			current->link = NULL;
			pthread_mutex_unlock(&current->lock); 
			pthread_mutex_unlock(&prev->lock);
			return current; 
		} 
		pthread_mutex_unlock(&prev->lock);
		prev = current; 
	} 
    pthread_mutex_unlock(&prev->lock); 
    return NULL; 
}

struct listenerNode	*linkListenerNode(struct listenerNode *head, struct listenerNode *node, struct sourceRecord *sPtr, unsigned char log)
{
	float ucCount;
	unsigned short ucLimit;
	unsigned char ucCheck;
	struct listenerNode	*prev, *current; 
	char *str;
	
	prev = head; 
	
	if(sPtr)
		ucLimit = sPtr->relay_limit;
	else
		ucLimit = 0xffff;

	ucCount = 0.0;
	if(node->rr.relay){
		// rsp relay... setup preroll for new stream if it is NOT a static relay... no pre-roll to static relays
		// since static relays are usually used for feeds and cross connects to other servers,
		// and not a cluster listener, as cluster listeners already have pre-roll handles by their original server.
		if((node->relayType == 0) && sPtr){
			if((sPtr->prerollPace > 0) && !node->keep && !node->rr.relay_cluster){
				// set to start prerolling at the fist packet prior to the current preroll index
				// setting endCol and endBlk to 255 is a flag to indicate that the preroll position
				// needs to be calculated... both are invalid values for normal operation.  This is 
				// only done if the request has relay_cluster = 1, so that clusters do no participlate
				// in pre-rolling, only the server to which the original request was made will  
				// pre-roll if it's in a cluster group.
				node->pr_curBlk = 0;
				node->pr_endBlk = 255;
				node->pr_curCol = 0;
				node->pr_endCol = 255;
			}else{
				// no prerolling
				node->pr_curBlk = 0;
				node->pr_endBlk = 0;
				node->pr_curCol = 0;
				node->pr_endCol = 0;
			}
			
		}
		ucCheck = TRUE;
	}else
		ucCheck = FALSE;
	
	// check counts, etc
	pthread_mutex_lock(&prev->lock); 
	while(current = prev->link){ 
		pthread_mutex_lock(&current->lock); 
		pthread_mutex_unlock(&prev->lock);
		if(ucCheck && current->rr.relay){
			if(current->rr.relay_cluster)
				// factional count for cluster listeners
				ucCount = ucCount + (1.0 / current->rr.relay_cluster);
			else
				ucCount++;	
		}
		prev = current; 
	} 
	pthread_mutex_unlock(&prev->lock);
	if(!ucCheck || (ucCount < ucLimit)){
		// link at START of list... this way, any reports that come in ahead of a static relay will time out and be deleted after 
		// the static relay has been added
		pthread_mutex_lock(&head->lock); 
		node->link = head->link;
		head->link = node;
		pthread_mutex_unlock(&head->lock);
		if(log && node->rr.meta && (str = cJSON_PrintUnformatted(node->rr.meta))){
			syslog(LOG_INFO, "new listener [UID=%u, info=%s]", node->UID, str);
			free(str);
		}
		return node;
	}
	return NULL;
}

struct listenerNode *findListenerNode(struct recvrRecord *RR, struct listenerNode *head)
{
	// if found, the node is returned in the locked state.
	// Do not hold the lock for long!

	unsigned int hash;	
	
	struct listenerNode	*prev, *current; 
	prev = head;

	if(RR->via){
		// use stated address and via
		hash = ELFHash(0, (char *)&(RR->statedAddress), sizeof(struct sockaddr_in6));
		hash = ELFHash(hash, RR->via, strlen(RR->via));

		pthread_mutex_lock(&prev->lock); 
		while((current = prev->link) != NULL){ 
			pthread_mutex_lock(&current->lock); 
			if(current->hash == hash){ 				
				// hash matches, check for port number matches and then do a full memory compare...
				if(current->rr.statedAddress.sin6_port == RR->statedAddress.sin6_port){
					if(memcmp(&(current->rr.statedAddress), &(RR->statedAddress), sizeof(struct sockaddr_in6)) == 0){
						if(current->rr.via && (strcmp(RR->via, current->rr.via) == 0)){
							// a match!
							pthread_mutex_unlock(&prev->lock);
							return current;
						}
					}
				}		
			} 
			pthread_mutex_unlock(&prev->lock);
			prev = current; 
		} 
		pthread_mutex_unlock(&prev->lock); 
		
	}else{
		// use apparent address
		hash = ELFHash(0, (char *)&(RR->apparentAddress), sizeof(struct sockaddr_in6));

		pthread_mutex_lock(&prev->lock); 
		while((current = prev->link) != NULL){ 
			pthread_mutex_lock(&current->lock); 
			if(current->hash == hash){ 
				// hash matches, check for port number matches and then a full memory compare...
				if(current->rr.apparentAddress.sin6_port == RR->apparentAddress.sin6_port){
					if(memcmp(&(current->rr.apparentAddress), &(RR->apparentAddress), sizeof(struct sockaddr_in6)) == 0){
						if(!current->rr.via){
							// a match!
							pthread_mutex_unlock(&prev->lock);
							return current;
						}
					}	
				}		
			} 
			pthread_mutex_unlock(&prev->lock);
			prev = current; 
		} 
		pthread_mutex_unlock(&prev->lock); 
	}
    return NULL; 
}

unsigned short readConfigFile(FILE * fd, cJSON **root_conf, cJSON **sources, cJSON **relay_conf, cJSON **reports_conf)
{
	long len;
	char *data;
	unsigned char count;
	
	*root_conf = NULL;
	*relay_conf = NULL;
	*reports_conf = NULL;
	*sources = NULL;
	count = 0;
	
	fseek(fd, 0, SEEK_END);
	len = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	
	data = (char *)malloc(len + 1);
	data[len] = 0;
	fread(data, 1, len, fd);
	if(*root_conf = cJSON_Parse(data)){
		*reports_conf = cJSON_GetObjectItem(*root_conf, "reports");		
		// look for rsp relay source settings
		if(*relay_conf = cJSON_GetObjectItem(*root_conf, "relay")){		
			if(*sources = cJSON_GetObjectItem(*relay_conf, "sources"))
				count = cJSON_GetArraySize(*sources);
		}
	}
	free(data);	
	return count;
}

void recodeRelaySetup(struct sourceRecord *sPtr, cJSON *recode)
{
	unsigned char rspErr;
	cJSON *item;
	struct rspSession *recodeSession;
	
	recodeSession = rspSessionNew(clientID);

	if(item = cJSON_GetObjectItem(recode, "FEC"))
		recodeSession->FECroots = item->valueint;
	else
	   goto fail;
	
	if(item = cJSON_GetObjectItem(recode, "Payload"))
		recodeSession->colSize = item->valueint;
	else
		goto fail;
		  
	if(item = cJSON_GetObjectItem(recode, "Interleave"))
		recodeSession->interleaving = item->valueint;
	else
	   goto fail;

	recodeSession->flags = 0;
	if(item = cJSON_GetObjectItem(recode, "RS")){
		if(item->valueint)
			recodeSession->flags |= RSP_FLAG_RS;
	}
	if(item = cJSON_GetObjectItem(recode, "CRC")){
		if(item->valueint)
			recodeSession->flags |= RSP_FLAG_CRC;
	}
		  
	if(item = cJSON_GetObjectItem(recode, "PrivateKeyFile")){
		if(item->valuestring && strlen(item->valuestring)){
			FILE *keyFile = fopen(item->valuestring, "r");				// Open the specified private key file
			if(keyFile == NULL)
				goto fail;
			rspErr = rspSessionSetPrivKeyFile(recodeSession, keyFile, "");	
			fclose(keyFile);										
			if(rspErr)
				goto fail;
		}
	}
	rspSessionClear(recodeSession, TRUE);
	if(rspSessionInit(recodeSession) == RSP_ERROR_NONE){
		sPtr->recode_rsp = recodeSession;
		return;
	}
	   
fail:
	rspSessionFree(recodeSession);
	sPtr->recode_rsp = NULL;
}

struct sockaddr_in6 *setSockAddr(struct sockaddr_in6 *adrPtr, unsigned char ip6, unsigned short port, const char *addr)
{
	unsigned int size;
	struct sockaddr_in *v4bindAddr;
	struct in6_addr v6bindto;
	u_int32_t v4bindto;
	
	if(ip6){
		// IPv6 network settings
		size = sizeof(struct sockaddr_in6);
		bzero(adrPtr, size);
#ifndef __linux__
		adrPtr->sin6_len = sizeof(struct sockaddr_in6);
#endif
		if(inet_pton(AF_INET6, addr, &v6bindto) <= 0)
			return NULL;
		adrPtr->sin6_family = AF_INET6;
		adrPtr->sin6_addr = v6bindto;
		adrPtr->sin6_port = htons(port);
	}else{
		size = sizeof(struct sockaddr_in6);
		bzero(adrPtr, size);
		v4bindAddr = (struct sockaddr_in *)adrPtr;
#ifndef __linux__
		v4bindAddr->sin_len = sizeof(struct sockaddr_in);
#endif
		if(inet_pton(AF_INET, addr, &v4bindto) <= 0)
			return NULL;
		v4bindAddr->sin_family = AF_INET;
		v4bindAddr->sin_addr.s_addr = v4bindto;
		v4bindAddr->sin_port = htons(port);
	}
	return adrPtr;
}

int serverNetworkSetup(cJSON *conf, unsigned char ip6, int mode) 
{
	cJSON *group, *item;
	int port, sd;
	unsigned int size;
	char *bindTo;
	struct sockaddr_in6 bindAddr;
	struct timeval tv;
	int trueVal = 1;
	
	sd = -1;
	port = 0;
	bindTo = NULL;
	if(ip6){
		// look for IPv6 network settings 
		if((group = cJSON_GetObjectItem(conf, "IP6")) == NULL)
			return -1;
		if(item = cJSON_GetObjectItem(group, "Port"))
			port = item->valueint;
		if(item = cJSON_GetObjectItem(group, "Bind"))
			bindTo = item->valuestring;
		if(bindTo == NULL)
			goto fail;
		if(setSockAddr(&bindAddr, TRUE, port, bindTo) == NULL)
			goto fail;
		if((sd = socket(AF_INET6, mode, IPPROTO_IP)) < 0)
			goto fail;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(trueVal));
		size = sizeof(struct sockaddr_in6);
		if(bind(sd, (struct sockaddr *)&bindAddr, size) < 0)
			goto fail;
	}else{
		// look for old (IPv4) network settings
		if((group = cJSON_GetObjectItem(conf, "IP4")) == NULL)
			return -1;
		if(item = cJSON_GetObjectItem(group, "Port"))
			port = item->valueint;
		if(item = cJSON_GetObjectItem(group, "Bind"))
			bindTo = item->valuestring;
		if(bindTo == NULL)
			goto fail;
		if(setSockAddr(&bindAddr, FALSE, port, bindTo) == NULL)
			goto fail;
		if((sd = socket(AF_INET, mode, IPPROTO_IP)) < 0)
			goto fail;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(trueVal));
		size = sizeof(struct sockaddr_in);
		if(bind(sd, (struct sockaddr *)&bindAddr, size) < 0)
			goto fail;
	}
	// thirty second receive time out... let us do house keeping if nothing is received in 30 seconds.
	tv.tv_sec = 30;  
	tv.tv_usec = 0;  
	if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) < 0)
		goto fail;
	
	return sd;
	
fail:
	if(sd >= 0)
		close(sd);
	return -1;
}	

int multicastSocketSetup(struct serverContext *cPtr, unsigned char ttl)
{
	cJSON *group, *item;
	int sd;
	unsigned int size;
	char *bindTo;
	struct sockaddr_in6 bindAddr;
	int trueVal = 1;
	
	sd = -1;
	bindTo = NULL;
	if(group = cJSON_GetObjectItem(cPtr->root_conf, "IP6")){
		// IPv6 network settings found
		if(item = cJSON_GetObjectItem(group, "Bind"))
			bindTo = item->valuestring;
		if(bindTo == NULL)
			goto fail;
		if(setSockAddr(&bindAddr, TRUE, 0, bindTo) == NULL)
			goto fail;
		if((sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0)
			goto fail;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(trueVal));
		size = sizeof(struct sockaddr_in6);
		if(bind(sd, (struct sockaddr *)&bindAddr, size) < 0)
			goto fail;
	}else{
		// look for old (IPv4) network settings
		if((group = cJSON_GetObjectItem(cPtr->root_conf, "IP4")) == NULL)
			return -1;
		if(item = cJSON_GetObjectItem(group, "Bind"))
			bindTo = item->valuestring;
		if(bindTo == NULL)
			goto fail;
		if(setSockAddr(&bindAddr, FALSE, 0, bindTo) == NULL)
			goto fail;
		if((sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
			goto fail;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(trueVal));
		size = sizeof(struct sockaddr_in);
		if(bind(sd, (struct sockaddr *)&bindAddr, size) < 0)
			goto fail;
	}
	// set up multicast properties
	unsigned char value = 0;
	if(setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, (unsigned char *)&value, sizeof(value)) < 0){
		goto fail;
	}
	// note: bind to the same interface the relay socket is bound to...
	if(setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&bindAddr, sizeof(bindAddr)) < 0){
		goto fail;
	}
	// multicast variable is zero for no multicast, otherwise it contains the TTL value for the multicast hop threshold
	if(setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, (unsigned char *)&ttl, sizeof(ttl)) < 0){
		goto fail;
	}
	
	return sd;
	
fail:
	if(sd >= 0)
		close(sd);
	return -1;
}

unsigned char checkForClustering(struct recvrRecord	*rr, unsigned char *packet, unsigned char *colNumber)
{
	// first time a packet is processed, colNumber = 0xff so we know to calculate the column number from the packet
	// and not have to do it again on subsequent use of the same packet
	if(rr->relay && rr->relay_cluster){
		if(*colNumber == 0xff){
			// new packet being check
			unsigned short col;	// unsigned short instead of unsigned char so range can handle math further on in this code
			if((packet[0] & 0x03) == RSP_FLAG_PAYLOAD){
				col = packet[2];
			}else if((packet[0] & 0x03) == RSP_FLAG_EXT){
				col = packet[4];
			}else if((packet[0] & 0x03) == RSP_FLAG_AUTH){
				// No column number in authentication packets: use the the lease significant byte of the CRC32, to 
				// decide/randomize which cluster server number will send this packet.
				col = packet[276];
				// col = 0xff is an invalid column number, so just set it to zero.  Were just randomizing anyway.
				if(col == 0xff)
					col = 0;
			}else{
				// send all other packets: report/request packets
				return 1;
			}
			if(col == 255)
				// send all reset packets
				return 1;
			// save colNumber for next time if we are checking the same packet for a new listener
			*colNumber = col;
		}
		// send only some intereaver colums... i.e. third column out of every four
		// where relay-1 is column modulus, and relay_cluster is the out-of count, starting at block/column 0,0
		if(((*colNumber) % rr->relay_cluster) == (rr->relay - 1))
			return 1;
		return 0;
	}
	// no clustering requested... send all
	return 1;
}

void sendPacketToListeners(struct serverContext *cPtr, struct sourceRecord *sPtr, unsigned char *packet, unsigned int size, unsigned char *payload)
{	
	struct listenerNode	*prev, *current; 
	struct rspSession *session;
	unsigned short i;
	size_t pr_size;
	unsigned char pr_packet[277];
	unsigned char pr_set, pr_last_col;

	// note: payload is set to point to the first non-header byte of packet payload data IF this is a 
	// payload packet - i.e. not a authentication or message packet.  This tells us we can send pre-roll
	// data too, if requested.
	
	// if this is an auth packet, and authBlock is true, don't send anything.
	if(((packet[0] & 0x03) == RSP_FLAG_AUTH) && (sPtr->authBlock))
		return;
	
	if(sPtr->recode_rsp)
		session = sPtr->recode_rsp;			
	else
		session = sPtr->rsp;

	unsigned char tempBuff[session->interleaver->rows];
	
	if(rspPacketInit(pr_packet, session->flags, session->colSize, NULL))
		pr_set = TRUE;
	else
		pr_set = FALSE;

	prev = sPtr->listHead;
	
	pthread_mutex_lock(&prev->lock); 
	while(current = prev->link){ 
		unsigned char colNumber = 0xff;
		pthread_mutex_lock(&current->lock); 
		pthread_mutex_unlock(&prev->lock);
		// see if this is a listener we are to relay to...
		if((current->rr.relay || current->keep) && (current->relayType == 0) && (((packet[0] & 0x03) != RSP_FLAG_AUTH) || (!current->authBlock))){
			// this is a RSP relay or static listener: send the packet
			
			// check for clustering
			if(checkForClustering(&current->rr, packet, &colNumber)){
				if(current->socket > -1)
					rspSendto(current->socket, packet, size, 0, (struct sockaddr*)&current->rr.apparentAddress);
				else
					contextSendTo(cPtr, packet, size, (struct sockaddr*)&current->rr.apparentAddress);
			}
			
			// check for pre-roll sending
			if(pr_set && payload && sPtr->prerollPace && (((packet[0] & 0x03) == RSP_FLAG_PAYLOAD) || ((packet[0] & 0x03) == RSP_FLAG_EXT))){
				if((current->pr_endCol != current->pr_curCol) || (current->pr_endBlk != current->pr_curBlk)){
					if((current->pr_endBlk == 255) && (current->pr_endCol == 255)){
						// flag to set initial preroll positions... use the current packet column and block values 
						// to calculate pre-roll start (cur) and end points.
						unsigned char blk, col;
						if((packet[0] & 0x03) == RSP_FLAG_PAYLOAD){
							blk = packet[1];
							col = packet[2];
						}else{
							blk = packet[3];
							col = packet[4];
						}					
						float pos, i;						
						pos = (((float)col + modff((float)blk / (float)session->interleaving, &i)) / 255.0) + i;						
						pos = pos - (kTargetWrRdGap * 0.9); // slightly ahead of the expected read position of kTargetWrRdGap blocks
						if(pos < 0)
							pos = pos + 3;
						pos = modff(pos, &i) * (float)session->interleaving;
						current->pr_curBlk = (unsigned char)(i * session->interleaving) +  (unsigned char)pos;
						current->pr_endBlk = (1 + (blk / session->interleaver->ratio)) * session->interleaver->ratio - 1;
						current->pr_endCol = col;
						current->pr_curCol = 0;
					}
					// send pre-roll packets... these are sent by incrementing the row index, then 
					// if row rollover, the block number to track with row reading playback.
					
					for(i=0; i<sPtr->prerollPace; i++){
						il_copyColumn(session->interleaver, tempBuff, current->pr_curCol, current->pr_curBlk);
						if(pr_size = rspPacketPayloadSet(pr_packet, tempBuff, session->network_rs, current->pr_curCol, current->pr_curBlk, session->FECroots, session->interleaving, session->crc_table)){
							if(current->socket > -1)
								rspSendto(current->socket, pr_packet, pr_size, 0, (struct sockaddr*)&current->rr.apparentAddress);
							else
								contextSendTo(cPtr, pr_packet, pr_size, (struct sockaddr*)&current->rr.apparentAddress);
						}
						// move to next preroll column
						if((current->pr_curBlk / session->interleaver->ratio) == (current->pr_endBlk / session->interleaver->ratio))
							pr_last_col = current->pr_endCol;
						else
							pr_last_col = 254;
						current->pr_curCol++;
						if(current->pr_curCol > pr_last_col){
							// column rollover
							current->pr_curCol = 0;
							current->pr_curBlk++;
						}
						if(current->pr_curBlk >= (3 * session->interleaver->ratio))
							// see if any of the above cause a full interleaver block rollover
							current->pr_curBlk = 0;
						if((current->pr_endCol == current->pr_curCol) && (current->pr_endBlk == current->pr_curBlk))
							break;
					}
				}				
				
			}
						
		}
		prev = current; 
	} 
	pthread_mutex_unlock(&prev->lock);
}

unsigned char transcoderExecute(struct sourceRecord *sPtr, cJSON *transcode)
{
	char **argv;
	cJSON *tcSettings, *item, *root, *value;
	int count, i, fd, sockpair[2];
	pid_t child;
	
//debugSession = sPtr->rsp;
	
	// check for and set the Content meta data for the re-coded stream
	if((tcSettings = cJSON_GetObjectItem(transcode, "Content")) == NULL)
		return FALSE;
	
	item = cJSON_CreateObject();
	srand(time(NULL));
	unsigned int mIDVal;
	while(((mIDVal = rand()) & 0xffff) == 0);
	cJSON_AddNumberToObject(item, "mID", mIDVal);
	if(((value = cJSON_GetObjectItem(tcSettings, "Type")) == NULL) || (value->valuestring == NULL) || (strlen(value->valuestring)== 0)){
		cJSON_Delete(item);
		return FALSE;
	}
	cJSON_AddStringToObject(item, "Type", value->valuestring);

	if(((value = cJSON_GetObjectItem(tcSettings, "Channels")) == NULL) || (value->valueint == 0)){
		cJSON_Delete(item);
		return FALSE;
	}
	cJSON_AddNumberToObject(item, "Channels", value->valueint);

	if(((value = cJSON_GetObjectItem(tcSettings, "kBitRate")) == NULL) || (value->valueint == 0)){
		cJSON_Delete(item);
		return FALSE;
	}
	cJSON_AddNumberToObject(item, "kBitRate", value->valueint);
	
	if(((value = cJSON_GetObjectItem(tcSettings, "SampleRate")) == NULL) || (value->valueint == 0)){
		cJSON_Delete(item);
		return FALSE;
	}
	cJSON_AddNumberToObject(item, "SampleRate", value->valueint);
	
	root =  cJSON_CreateObject();
	cJSON_AddItemToObject(root, "Content", item);
	rspSessionQueueMetadata(sPtr->recode_rsp, root, NULL);
	
	// configure the transcoder
	if((tcSettings = cJSON_GetObjectItem(transcode, "transcoder")) == NULL)
		return FALSE;
	if((count = cJSON_GetArraySize(tcSettings)) == 0)
		return FALSE;
	if((argv = (char **)malloc(sizeof(char*) * (count+1))) == NULL)
		return FALSE;
	for(i=0; i<count; i++){
		if((item = cJSON_GetArrayItem(tcSettings, i)) == NULL)
			break;
		if((item->valuestring == NULL) || (strlen(item->valuestring) == 0))
			break;
		argv[i] = item->valuestring;
	}
	argv[i] = NULL;
	
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair) < 0){
		free(argv);
		return FALSE;
	}
	// execute it;
	if((child = fork()) < 0){
		free(argv);
		close(sockpair[0]);
		close(sockpair[1]);
		return FALSE;
	}else if(child == 0){
		// if we are the forked child
		
		// unblock all signals and set to default handlers
		sigsetmask(0);
		// obtain a new process group 
		setsid();
		// Redirect standard input from socketpair
		if(dup2(sockpair[0], STDIN_FILENO) == STDIN_FILENO){ 
			// Redirect standard output to socketpair
			if(dup2(sockpair[0], STDOUT_FILENO) == STDOUT_FILENO){
				// Redirect standard err to /dev/null
				if(dup2(open("/dev/null", O_WRONLY), STDERR_FILENO) == STDERR_FILENO){
//				if(dup2(open("/tmp/debug_stderr.txt", O_CREAT | O_RDWR), STDERR_FILENO) == STDERR_FILENO){
					// close all other descriptors
					for(fd=getdtablesize(); fd >= 0; --fd){
						if((fd != STDERR_FILENO) && (fd != STDIN_FILENO) && (fd != STDOUT_FILENO))
							close(fd); 
					}
					// enable parent tracing of this process so the parent can detect sucess or failure of the exec that will follow
					ptrace(PT_TRACE_ME, 0, NULL, 0);
					// and run...	
					execvp(argv[0], argv);
				}
			}
		}
		syslog(LOG_ERR, "transcode exec failed with error %m");
		exit(0);
		
	}else{
		// parent continues here...
		close(sockpair[0]);
		free(argv);
		// wait to see if the transcoder ran
		int val;
		while(waitpid(child, &val, 0) < 0)
			sleep(1);
		if(WIFSTOPPED(val)){
			// exec ok... let the child continue
			ptrace(PT_DETACH, child, NULL, 0);
			// set sockets to non-blocking... processStreamData function will check for available read data when it writes new data out.
			val = fcntl(sockpair[1], F_GETFL, 0);
			fcntl(sockpair[1], F_SETFL, val | O_NONBLOCK);
			// set the source record transcoder socket to this socket
			sPtr->tc_socket = sockpair[1];
			sPtr->child = child;
			return TRUE;
		}
		// otherwise something went wrong with the child
		close(sockpair[1]);
		sPtr->tc_socket = -2;
		return FALSE;
	}
}

void updateMetaString(char **sc_meta)
{
	unsigned char pad;
	char *new_str;
	unsigned int count;
	
	new_str = NULL;
	appendstr(&new_str, "*StreamTitle='");	// NOTE: * will be replaced by string count
	if(sc_meta[1])
		appendstr(&new_str,sc_meta[1]);
	if(sc_meta[3]){
		appendstr(&new_str, "';StreamURL='");
		appendstr(&new_str,sc_meta[3]);
	}else if(sc_meta[2]){
		appendstr(&new_str, "';StreamURL='");
		appendstr(&new_str,sc_meta[2]);
	}
	appendstr(&new_str, "';");
	
	// size the sc_meta string
	count = strlen(new_str);
	// truncate to sc metadata size constraint if needed
	if(count > 4081)
		count = 4081;
	if(pad = ((count - 1) % 16)){
		// pad to 16 bytes, less first byte
		pad = 16 - pad;
		appendbytes(&new_str, &count, (char *)empty, pad);
	}
	// first byte is string byte count / 16
	*new_str = (count - 1) / 16;
	
	if(sc_meta[0])
		free(sc_meta[0]);
	sc_meta[0] = new_str;
	
}

unsigned char shoutcastSendBuffer(struct listenerNode *listener, char **sc_meta, unsigned int sc_metaperiod, unsigned char *data, unsigned int *size)
{
	unsigned char *sc_mptr;
	unsigned int msize; 
	int scfrag;
	char tmp[16];
	int err;
	

	// cap size to next meta period
	if(listener->offset < 0){
		// NOT interleaving metadata, just use the size
		scfrag = *size;
	}else{
		// we are interleaving metadata, send only upto the next metadata chunk if less than size
		if((scfrag = sc_metaperiod - listener->offset) > *size)
			scfrag = *size;
	}
		
	if(scfrag)
		scfrag = send(listener->socket, data, scfrag, 0);
	if(scfrag < 0){
		err = errno;
		if((err == EAGAIN) || (err == EWOULDBLOCK)){
			// use read to test for remote socket closure
			if(read(listener->socket, &tmp, sizeof(tmp)) == 0)
				// socket closed!
				return TRUE;
			else{
				*size = 0;
				return FALSE;
			}
		}else
			return TRUE;
	}else{ 
		// Update counters and pointers
		*size = scfrag;
		if(listener->offset >= 0){
			// ONLY if we are interleaving metadata
			listener->offset = listener->offset + scfrag;
			if(listener->offset == sc_metaperiod){					
				// send meta data
				if((sc_meta[0] == NULL) || (listener->mptr == sc_meta[0]))
					sc_mptr = empty;
				else{
					sc_mptr = (unsigned char *)sc_meta[0];
					listener->mptr = (char *)sc_mptr;											
				}
				msize = (*sc_mptr * 16) + 1;
				if(send(listener->socket, sc_mptr, msize, 0) != msize){
					err = errno;
					if((err == EAGAIN) || (err == EWOULDBLOCK)){
						// use read to test for remote socket closure
						if(read(listener->socket, &tmp, sizeof(tmp)) == 0)
							// socket closed!
							return TRUE;
						else
							return FALSE;
					}else
						return TRUE;
				}
				listener->offset = 0;

			}
		}
	}
	return FALSE;
}
	
void shoutcastRelayData(struct serverContext *cPtr, struct sourceRecord *sPtr, unsigned char *data, unsigned int size, char **sc_meta)
{
	unsigned int count;
	struct listenerNode *current, *prev;
	unsigned char *dataPtr;
	unsigned char packet[277];
	unsigned char report, flag, roll;
	unsigned int scfrag;
	int idxDiff;
	char *sc_report;
	cJSON *meta;
	cJSON *item;
	
	// copy new data into shoutcast pre-roll buffer, if it is allocated
	if((sPtr->sc_prerollIdx == 0) && !sPtr->sc_prerollFill)
		// pre-roll was reset... reset listeners too...
		flag = TRUE;
	else
		flag = FALSE;
	count = size;
	dataPtr = data;
	// we need to lock the source for this because we will be using the sc_prerollBuf
	// and we can't have that modified by a setting reload while we are using it.
	pthread_mutex_lock(&sPtr->lock);
	roll = FALSE;
	while(scfrag = count){
		if(scfrag > ((sPtr->sc_prerollSize * 2)- sPtr->sc_prerollIdx))
			scfrag = (sPtr->sc_prerollSize * 2) - sPtr->sc_prerollIdx;
		memcpy(sPtr->sc_prerollBuf + sPtr->sc_prerollIdx, dataPtr, scfrag);
		sPtr->sc_prerollIdx = sPtr->sc_prerollIdx + scfrag;
		if(!sPtr->sc_prerollFill && (sPtr->sc_prerollIdx >= sPtr->sc_prerollSize))
			sPtr->sc_prerollFill = TRUE;
		if(sPtr->sc_prerollIdx >= (sPtr->sc_prerollSize * 2)){
			sPtr->sc_prerollIdx = sPtr->sc_prerollIdx - (sPtr->sc_prerollSize * 2);
			roll = TRUE;
		}
		count = count - scfrag;
		dataPtr = dataPtr + scfrag;
	}
	
	// Shoutcast send here for items of relayType = 1 or 2
	prev = sPtr->listHead;
	
	if((cPtr->sc_reportperiod + sPtr->sc_lastreport) < time(NULL))
		report = 1;
	else
		report = 0;
	
	pthread_mutex_lock(&prev->lock); 
	while(current = prev->link){ 
		pthread_mutex_lock(&current->lock); 
		// see if this is a listener we are to relay to...
		if((current->socket > -1) && current->rr.relay && ((current->relayType == 1) || (current->relayType == 2))){
			// this is a shoutcast relay: send the packet
			if(flag || (current->relayType == 2)){
				// handle preroll: set this listeners stream index
				if(sPtr->sc_prerollFill){
					// set streaming index for this listener to the current buffer
					// position minus the buffer size: send the whole buffer
					// Must handle index rollover too.
					int index;
					index = sPtr->sc_prerollIdx - sPtr->sc_prerollSize;
					if(index < 0)
						// actual buffer is twice the perscribed preroll size
						index = index + (sPtr->sc_prerollSize * 2);
					current->pr_Idx = (unsigned int)index;
					
				}else{
					// buffer has not filled yet, start at index 0
					current->pr_Idx = 0;
				}
				current->relayType = 1;
			}
			// send session data chunks until we would either block, reach the rate cap
			// or catch up with the source buffer index
			idxDiff = sPtr->sc_prerollIdx - current->pr_Idx;
			if(roll)
				// adjust underrun statistics-> time constant: 2/(1-k) - 1 = 2/(1-0.9802) - 1 = 100
				// square k due to roll-over after TWO buffers, not one.
				current->rr.FECStat = current->rr.FECStat * 0.9608;							
			if(idxDiff <= 0)
				// handle write wrap-around
				// actual buffer is twice the perscribed preroll size
				idxDiff = idxDiff + (sPtr->sc_prerollSize * 2);
			if(idxDiff > (signed int)sPtr->sc_prerollSize){
				// buffer underrun... adjust index and count to cover the data just added.
				int index;
				
				idxDiff = size;
				index = sPtr->sc_prerollIdx - idxDiff;
				// again, actual buffer is twice the perscribed preroll size
				if(index < 0)
					index = index + (sPtr->sc_prerollSize * 2);
				current->pr_Idx = (unsigned int)index;
				// adjust underrun statistics-> time constant: 2/k - 1 = 2/0.0198 - 1 = 100
				// scaled to 100%
				current->rr.FECStat = current->rr.FECStat + (0.0198 * 100.0);
				current->rr.ErrStat = current->rr.ErrStat + 1.0;
				// check under-run limit
				if(current->rr.FECStat > sPtr->sc_underrun_limit){
					// under-run limit exceeded... delete listener
					prev->link = current->link;
					pthread_mutex_unlock(&current->lock);
					if(cPtr->log_listeners)
						syslog(LOG_INFO, "shoutcast under-run limit exceeded [UID=%u]", current->UID);
					freeListenerNode(current, cPtr->log_listeners);
					current = NULL;
				}
			}else if(count = idxDiff){
				unsigned int rate;
				if((rate = (sPtr->prerollPace + 1)) <= 1)
					// set the rate cap at twice the data rate MINIMUM
					rate = 2;
				if(count > (rate * size))
					// cap the rate to catch up if needed
					count = rate * size;
				// read upto the end of the buffer only... if it's short, we will make up for it next time
				// again, actual buffer is twice the perscribed preroll size
				if((current->pr_Idx + count) > (sPtr->sc_prerollSize * 2)){
					count = (sPtr->sc_prerollSize * 2) - current->pr_Idx;
				}
				if(shoutcastSendBuffer(current, sc_meta, cPtr->sc_metaperiod, sPtr->sc_prerollBuf + current->pr_Idx, &count)){
					// serious socket error returned
					prev->link = current->link;
					pthread_mutex_unlock(&current->lock);
					freeListenerNode(current, cPtr->log_listeners);
					current = NULL;
					
				}else if(count > 0){
					// move index and handle possible rollover
					current->pr_Idx = current->pr_Idx + count;
					// again, actual buffer is twice the perscribed preroll size
					if(current->pr_Idx >= sPtr->sc_prerollSize * 2)
						current->pr_Idx = current->pr_Idx - (sPtr->sc_prerollSize * 2);
				}
			}
			
			if(current && report)
				current->rr.lastHeard = time(NULL);
			
			if(current && cPtr->sc_reportperiod && cPtr->forwardAddress.sin6_family && report){
				// update and send a RSP report packet for this shoutcast listener	
				if(meta = cJSON_GetObjectItem(current->rr.meta, "Report")){
					if(item = cJSON_GetObjectItem(meta, "Fix"))
						item->valuedouble = round(current->rr.FECStat);
					if(item = cJSON_GetObjectItem(meta, "Fail"))
						item->valuedouble = round(current->rr.ErrStat);
					current->rr.BalStat = round(-100. * (idxDiff / (signed int)sPtr->sc_prerollSize));
					if(item = cJSON_GetObjectItem(meta, "Bal"))
						item->valuedouble = round(current->rr.BalStat);
				}  
				if(sc_report = cJSON_PrintUnformatted(current->rr.meta)){
					// format packet and send
					count = strlen(sc_report) + 1;
					if((count > 0) && (count <= 240)){
						if(count % 16)
							count = count + 16;
						count = (count / 16) * 16;
						bzero(packet, count + 1);
						packet[0] = RSP_FLAG_RR | ((count - 16) & 0xF0);
						memcpy(packet + 1, sc_report, strlen(sc_report));
						pthread_mutex_lock(&cPtr->lock);
						contextSendTo(cPtr, packet, count+1, (struct sockaddr*)&cPtr->forwardAddress);
						pthread_mutex_unlock(&cPtr->lock);
					}
					free(sc_report);
				}	
			}
		}
		pthread_mutex_unlock(&prev->lock);
		if(current)
			prev = current; 
	} 
	pthread_mutex_unlock(&prev->lock);
	
	pthread_mutex_unlock(&sPtr->lock);
	if(report)
		sPtr->sc_lastreport = time(NULL);
	
}

void rspReformatRelayData(struct serverContext *cPtr, struct sourceRecord *sPtr, unsigned char *data, unsigned int size, char **metaStr, unsigned int *metaPos)
{
	unsigned int count;
	unsigned int rawFrameSize;		
	unsigned char *dataPtr;
	unsigned char *packetPtr;

	rawFrameSize = 255 - sPtr->recode_rsp->FECroots;
	// we are reformating RSP packets before sending to listeners
	count = size;
	dataPtr = data;
	while(count > 0){
		// data has come in from the source rsp session... re-frame it.  
		// NOTE: First byte of rawFrame is meta data, followed by audio data
		if(count < (signed int)((rawFrameSize - 1) - sPtr->rspfrag)){	// note 1 extra byte reserved for meta data stream
			// copy fragment
			memcpy(sPtr->reformFrame + sPtr->rspfrag + 1, dataPtr, count);
			sPtr->rspfrag = sPtr->rspfrag + count;
			count = 0;
		}else{
			// enough to fill a frame
			size = (rawFrameSize - 1) - sPtr->rspfrag;				// note 1 extra byte reserved for meta data stream
			memcpy(sPtr->reformFrame + sPtr->rspfrag + 1, dataPtr, size);
			sPtr->rspfrag = 0;
			count = count - size;
			dataPtr = dataPtr + size;
			
			if(*metaStr == NULL){
				// check to see if there is new metadata to start adding to frames
				if(*metaStr = rspSessionNextMetaStr(sPtr->recode_rsp))
					*metaPos = 0;						 
			}
			
			// set next metadataByte, if any
			if(*metaStr){
				if((sPtr->reformFrame[0] = (*metaStr)[(*metaPos)++]) == 0){
					// end of string
					free(*metaStr);
					*metaStr = NULL;
				}
			}else
				// No metadata: set metadata byte in packet to NULL char
				sPtr->reformFrame[0] = 0; 
			
			// we have a full frame... process through data RS encoder and write to interleaver row
			if(!rspSessionWriteData(sPtr->recode_rsp, sPtr->reformFrame, rawFrameSize)){
				// no error... check for packets comming out of interleaver to send
				unsigned char raw[sPtr->recode_rsp->interleaver->rows];
				while(size = rspSessionReadPacket(sPtr->recode_rsp, &packetPtr, raw))
					sendPacketToListeners(cPtr, sPtr, packetPtr, size, raw);
			}
		}
	}
}

unsigned char processStreamData(struct serverContext *cPtr, struct sourceRecord *sPtr, char **sc_meta, char **metaStr, unsigned int *metaPos, struct timespec *lastTime)
{
	unsigned int size;
	ssize_t rsize;
	unsigned int rawFrameSize;		
	unsigned char *data;
	unsigned char tc_buf[277];
	int err;
	char *tmpStr;
	cJSON *meta;
	cJSON *item;
	cJSON *track;
	cJSON *prop;
	
	if(((size = sPtr->retry_size) == 0) || ((data = sPtr->retry_data) == NULL)){
		// no transcoder socket blockage... look for new interleaver data
		if(!sPtr->sourceStatus && (rspSessionGetBalance(sPtr->rsp) < 0.00)){
			// need to fill buffer more and set last time to now as if we just performed a read.
			clock_gettime(CLOCK_MONOTONIC, lastTime);
			return FALSE;
		}
		// try to get more data from interleaver
		if(data = rspSessionPacedReadData(sPtr->rsp, &size, lastTime)){
			if(size){
				if(!sPtr->sourceStatus)
					// if we are reading data from the source RSP session, then the source must be up and running!
					sPtr->sourceStatus = TRUE;
				// check for meta data to note
				
				if(meta = rspSessionNextMetadata(sPtr->rsp)){					
					// check if we should creating metadata files in a specified metaDropDirectory
					// need to lock the source for this so the source_conf can't be changed while we check/use it.
					
					pthread_mutex_lock(&sPtr->lock);
					if(sPtr->source_conf && (item = cJSON_GetObjectItem(sPtr->source_conf, "metaDropDirectory"))){	
						char *tag, *dir, *path, *final;
						FILE *fp;
						if((dir = item->valuestring) && strlen(dir)){
							if(item = meta->child){
								if((tag = item->string) && strlen(tag)){
									if(tmpStr = cJSON_Print(item)){
										path = NULL;
										appendstr(&path, dir);
										if(path[strlen(path)-1] != '/')
											appendchr(&path, '/');
										appendstr(&path, tag);
										if(fp = fopen(path, "w")){
											fputs(tmpStr, fp);
											fclose(fp);
											final = NULL;
											appendstr(&final, path);
											appendstr(&final, ".json");
											rename(path, final);
											free(path);
											free(final);
										}
										free(tmpStr);		
									}
								}
							}
						}
					}
					pthread_mutex_unlock(&sPtr->lock);
					
					// "Cluster" object... setup cluster listening if we are in relay mode
					if(sPtr->rsp->relay && (item = cJSON_GetObjectItem(meta, "Cluster")))
						//handle new cluster list metadata	
						rspSessionClusterSetup(sPtr->rsp, item);
					
					// "Item" object (now playing track info), if any... keep last 10 plays AND reformat for shoutcast
					if(item = cJSON_GetObjectItem(meta, "item")){
						if(sc_meta[1]){
							free(sc_meta[1]);
							sc_meta[1] = NULL;
						} 
						track = cJSON_CreateObject();
						// keep only ID, Artist, Album and Title properties
						if(prop = cJSON_GetObjectItem(item, "mID"))
							cJSON_AddNumberToObject(track, "mID", prop->valueint);
						if(prop = cJSON_GetObjectItem(item, "Artist")){
							if(prop->valuestring){
								cJSON_AddStringToObject(track, "Artist", prop->valuestring);
								appendstr(&sc_meta[1], prop->valuestring);
							}
						}
						appendstr(&sc_meta[1], " - ");
						if(prop = cJSON_GetObjectItem(item, "Name")){
							if(prop->valuestring){
								cJSON_AddStringToObject(track, "Name", prop->valuestring);
								appendstr(&sc_meta[1], prop->valuestring);
							}
						}
						if(prop = cJSON_GetObjectItem(item, "Album")){
							if(prop->valuestring){
								cJSON_AddStringToObject(track, "Album", prop->valuestring);
							}
						}
						// replace ' with ` for shoutcast meta data
						replaceChar('\'', '`', sc_meta[1]);
					
						updateMetaString(sc_meta);
						
						// add time stamp to jSON object
						cJSON_AddNumberToObject(track, "When" ,time(NULL));
						pthread_mutex_lock(&sPtr->trackLock);
						cJSON_AddItemToArray(sPtr->trackList, track);
						while(cJSON_GetArraySize(sPtr->trackList) > 10)
							cJSON_DeleteItemFromArray(sPtr->trackList, 0);
						pthread_mutex_unlock(&sPtr->trackLock);
					}
					if(item = cJSON_GetObjectItem(meta, "message")){
						// reformat for shoutcast
						if(prop = cJSON_GetObjectItem(item, "text")){
							if(prop->valuestring && strlen(prop->valuestring)){
								if(sc_meta[2]){
									free(sc_meta[2]);
									sc_meta[2] = NULL;
								}
								appendstr(&sc_meta[2], prop->valuestring);
								// replace ' with ` for shoutcast meta data
								replaceChar('\'', '`', sc_meta[2]);
								
								updateMetaString(sc_meta);
								
							}
						}
					}
					if(item = cJSON_GetObjectItem(meta, "alert")){
						// reformat for shoutcast
						if(prop = cJSON_GetObjectItem(item, "text")){
							if(prop->valuestring && strlen(prop->valuestring)){
								if(sc_meta[3]){
									free(sc_meta[3]);
									sc_meta[3] = NULL;
								}
								appendstr(&sc_meta[3], prop->valuestring);
								// replace ' with ` for shoutcast meta data
								replaceChar('\'', '`', sc_meta[3]);
								
								updateMetaString(sc_meta);
							}
						}
					}else{
						if(sc_meta[3]){
							// Alert is set: check if it has expired
							pthread_mutex_lock(&(sPtr->rsp->metaMutex));
							if(!cJSON_GetObjectItem(sPtr->rsp->metaRepeat, "alert")){
								free(sc_meta[3]);
								sc_meta[3] = NULL;
								updateMetaString(sc_meta);
							}
							pthread_mutex_unlock(&(sPtr->rsp->metaMutex));
						}
					}


					if(sPtr->recode_rsp){
						if((sPtr->tc_socket < 0) || !cJSON_GetObjectItem(meta, "Content")){
							// pass all metadata along to the re-coding rsp session if we are not transcoding the stream
							// and pass all metadata other than "Content" if we are.
							if(tmpStr = cJSON_PrintUnformatted(meta)){
								if(item = cJSON_Parse(tmpStr))
									rspSessionQueueMetadata(sPtr->recode_rsp, item, sPtr->meta_exclude);
								free(tmpStr);
							}
						}
					}
					cJSON_Delete(meta);
				}else
					rspSessionExpiredMetaCheck(sPtr->rsp);
			}else{
				// size = 0 indicated an error: bad data?
				// mark source as down
				if(sPtr->sourceStatus){
					syslog(LOG_WARNING, "%s Source Down (break in stream continuity)", sPtr->sourceName);
					sPtr->sourceStatus = FALSE;
				}
			}
		}
	}
	// process new interleaver data, or retry on transcoder data that was previously blocked
	if(data && size){
		if(sPtr->tc_socket > -1){
			// run data through a transcoder via it's write-to socket
			if((rsize = write(sPtr->tc_socket, data, size)) != (signed)size){
				err = errno;
				if((err == EAGAIN) || (err == EWOULDBLOCK)){
					// socket would block... try again next time
					sPtr->retry_data = data;
					sPtr->retry_size = size;
					return FALSE;
				}else{
					syslog(LOG_ERR, "%s transcode socket write error %m: %ld of requested %u bytes writen", sPtr->sourceName, rsize, size);
					close(sPtr->tc_socket);
					sPtr->tc_socket = -2;
				}
			}
			sPtr->retry_data = NULL;
		}
		do{
			rsize = 0;
			if(sPtr->tc_socket > -1){
				// get data back from transcoder via it's read-back socket
				rawFrameSize = sPtr->recode_rsp->interleaver->columns - sPtr->recode_rsp->FECroots - 1;
				if((rsize = read(sPtr->tc_socket, tc_buf, rawFrameSize)) <= 0){
					if((rsize < 0) && (errno == EPIPE)){
						close(sPtr->tc_socket);
						sPtr->tc_socket = -2;
						sPtr->sourceStatus = FALSE;
					}
					break;
				}
				// replace original data and size with data pointer and size from socket read
				size = rsize;	
				data = tc_buf;
			}
			if(sPtr->tc_socket == -2)
				break;
			
			// Relay the rsp stream or transcoded data...
			
			// ****** shoutcast relay ******			
			if(sPtr->sc_prerollBuf && ((cPtr->sc_socket6 > -1) || (cPtr->sc_socket4 > -1)))
				shoutcastRelayData(cPtr, sPtr, data, size, sc_meta);
				
			// ****** Reformated RSP relay ******				
			if(sPtr->recode_rsp)	
				rspReformatRelayData(cPtr, sPtr, data, size, metaStr, metaPos);
				
		}while(rsize);
		return TRUE;
	}
	return FALSE;
}

unsigned short checkListenerTimeout(struct serverContext *cPtr, struct listenerNode *listHead, float *relay_count)
{
	struct listenerNode	*prev, *current; 
	time_t timenow;
	unsigned int records;
	float rcount;

	// check for listener timeouts
	records = 0;
	rcount = 0.0;
	prev = listHead;
	timenow = time(NULL);
	pthread_mutex_lock(&prev->lock); 
	while(current = prev->link){ 
		pthread_mutex_lock(&current->lock); 
		// only count listeners WE are relaying to
		if(relay_count && current->rr.relay){
			if(current->rr.relay_cluster)
				// factional count for cluster listeners
				rcount = rcount + (1.0 / current->rr.relay_cluster);
			else
				rcount++;
		}
		// now count total listener records
		records++;
		if((cPtr->relay_timeout) && ((timenow - cPtr->relay_timeout) > current->rr.lastHeard) && (!current->keep)){
			// last report time > timeout... delete listener
			prev->link = current->link;
			pthread_mutex_unlock(&current->lock);
			freeListenerNode(current, cPtr->log_listeners);
			continue;
		}
		pthread_mutex_unlock(&prev->lock);
		prev = current; 
	} 
	pthread_mutex_unlock(&prev->lock);
	if(relay_count)
		*relay_count = rcount;
	return records;
}

void *relayTask(void* refCon)
{
	struct serverContext *cPtr;
	struct sourceRecord *sPtr;
	struct relayPass *pass;
	struct timeval tv;
	struct timespec lastWr;
	struct timespec lastRd;
	unsigned char packet[277];
	unsigned int size;
	int count;
	char *sc_meta[4];	// [0] = full string, [1] = track, [2] = url/message, [3] = alert
	char *metaStr;
	unsigned int metaPos;
	unsigned char rsp_err;
	
	pass = (struct relayPass *)refCon;
	sPtr = pass->sPtr;
	cPtr = pass->cPtr;
	// signal the parent we are done with the structure pointer that was passed
	pass->cPtr = NULL;
	// initializes variables
	count = 0;
	sc_meta[0] = NULL;
	sc_meta[1] = NULL;
	sc_meta[2] = NULL;
	sc_meta[3] = NULL;
	metaStr = NULL;
	sPtr->rspfrag = 0;
	bzero(&lastWr, sizeof(struct timeval));
	bzero(&lastRd, sizeof(struct timeval));
	tv.tv_usec = 0;
	tv.tv_sec = 1;
	// Set 1 second initial network socket time out... will be set later for 
	// read pacing once the write rate has been established
	setsockopt(sPtr->rsp->clientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
	while(sPtr->run && cPtr->run && (count >= 0)){
		if((count = rspSessionNetworkRead(sPtr->rsp, FALSE)) > 0){	
			size = count;
			if(sPtr->rsp->interleaver == NULL){
				// Waiting to discover rsp format (via reception of extended payload packet)
				if(rspSessionFormatDiscover(sPtr->rsp, size) != RSP_ERROR_NONE)
					// not found yet... try again with another packet
					continue;
				else{
					if(sPtr->recode_rsp){
						// send reset packets out to rsp listeners
						unsigned int rst_size, i;
						if(rst_size = rspPacketResetSet(sPtr->recode_rsp->rsp_packet, sPtr->recode_rsp->network_rs, sPtr->recode_rsp->rsaPriv, sPtr->recode_rsp->crc_table)){
							for(i=0; i<5; i++)
								sendPacketToListeners(cPtr, sPtr, sPtr->recode_rsp->rsp_packet, rst_size, NULL);
						}
					}
					// and reset the pre-roll indexes
					sPtr->sc_prerollIdx = 0;
					sPtr->sc_prerollFill = FALSE;
				}
			}
			
			if((sPtr->recode_rsp == NULL) && (size <= sizeof(packet))) 
				// copy the raw packet so rsp processing doesn't modify the data to be resent to listeners
				memcpy(packet, sPtr->rsp->rsp_packet, size);
			if((rsp_err = rspSessionWritePacket(sPtr->rsp, &size, &lastWr)) == RSP_ERROR_NONE){
				// Packet is OK...
				if(sPtr->recode_rsp == NULL){	
					// Raw RSP relay
					// We are not reformating the RSP packets. Pass packet as is to listeners
					if((*packet & 0x03) == RSP_FLAG_EXT)
						sendPacketToListeners(cPtr, sPtr, packet, count, sPtr->rsp->rsp_packet+5);
					else
						sendPacketToListeners(cPtr, sPtr, packet, count, sPtr->rsp->rsp_packet+3);
				}
			}else if(rsp_err == RSP_ERROR_RRPCKT){
				// handle message from relay server, such as "server full"
				// Message string length in size variable
				// jSON formated message string is at session->rsp_packet + 1
				
				// just to be safe, make sure the last byte is a NULL so we can handle the data as a string
				*(sPtr->rsp->rsp_packet + 1 + size) = 0;
				syslog(LOG_WARNING, "Source [%s] server message: %s", sPtr->sourceName, sPtr->rsp->rsp_packet+1);
			}else if(!sPtr->sourceStatus && (rsp_err == RSP_ERROR_FORMAT)){
				// stream reset... clear rsp format and listen for new format to be advertised
				// note that rspSessionWritePacket function already does this if it detects a reset request.
				rspSessionClear(sPtr->rsp, FALSE);
				rsp_err = RSP_ERROR_RESET;
				// this will cause the us to wait for new format discovery next time through this loop.
			}
		}
		
		while(processStreamData(cPtr, sPtr, sc_meta, &metaStr, &metaPos, &lastRd));
		
		if(sPtr->rsp->wrRate > 0.0){
			// set new network read timeout, 1/2 the avr. write period		
			float i;
			struct timeval tv;
			tv.tv_usec = modff(0.5 * sPtr->rsp->wrRate, &i) * 1.0e6;
			tv.tv_sec = i;
			setsockopt(sPtr->rsp->clientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
		}
		if((sPtr->listener_count = checkListenerTimeout(cPtr, sPtr->listHead, &sPtr->relay_count)) > sPtr->listener_peak)
		   sPtr->listener_peak = sPtr->listener_count;
	}
	// send a request to relay server to stop sending stream packets
	rspPacketRecvrRequestSend(sPtr->rsp, NULL, RSP_RR_STOP);
	// shutdown transcoder socket, if any
	if(sPtr->tc_socket > -1){
		shutdown(sPtr->tc_socket, SHUT_RDWR);
		close(sPtr->tc_socket);
		sPtr->tc_socket = -2;
	}
	if(sc_meta[0])
		free(sc_meta[0]);
	if(sc_meta[1])
		free(sc_meta[1]);
	if(sc_meta[2])
		free(sc_meta[2]);
	if(sc_meta[3])
		free(sc_meta[3]);
	if(metaStr)
		free(metaStr);
	pthread_exit(0);
}

unsigned char startSourceRelayTask(struct serverContext *cPtr, struct sourceRecord *node)
{
	struct relayPass pass;
	pass.cPtr = cPtr;
	pass.sPtr = node;
	
	node->run = TRUE;
	if(pthread_create(&node->source_relay_thread, NULL, &relayTask, &pass) != 0){
		// return that there was an error
		return TRUE;
	}
	// wait for thread to finish using the passed structure
	while(pass.cPtr);
	// and return with no error
	return FALSE;
}

void linkSourceNode(struct sourceRecord *node, struct sourceRecord *head) 
{
	// link at START of list... 
	pthread_mutex_lock(&head->lock); 
	node->next = head->next;
	head->next = node;
	pthread_mutex_unlock(&head->lock);
}

struct sourceRecord *unlinkSourceNode(struct sourceRecord *node, struct sourceRecord *head) 
{
	struct sourceRecord	*prev, *current; 
	
	prev = head;
	pthread_mutex_lock(&prev->lock); 
	while((current = prev->next) != NULL){ 
		pthread_mutex_lock(&current->lock); 
		if(current == node){ 
			prev->next = current->next;
			current->next = NULL;
			pthread_mutex_unlock(&current->lock); 
			pthread_mutex_unlock(&prev->lock);
			return current; 
		} 
		pthread_mutex_unlock(&prev->lock);
		prev = current; 
	} 
    pthread_mutex_unlock(&prev->lock); 
    return NULL; 
}		

struct sourceRecord *newSourceNode(struct serverContext *cPtr)
{
	struct sourceRecord *rec;
	
	rec = (struct sourceRecord *)calloc(1, sizeof(struct sourceRecord));
	rec->listHead = newListenerNode(cPtr, NULL);
	pthread_mutex_init(&rec->trackLock, NULL);
	pthread_mutex_init(&rec->lock, NULL);
	rec->tc_socket = -1;
	rec->child = 0;
	return rec;
}

void freeSourceNode(struct sourceRecord *node, unsigned char log)
{
	struct listenerNode	*current, *prev;
	
	// need to stop relay thread, wait for it to end, etc.
	node->run = FALSE; 
	if(node->source_relay_thread){
		pthread_cancel(node->source_relay_thread);
		pthread_join(node->source_relay_thread, NULL);
	}
	if(node->sc_prerollBuf)
		free(node->sc_prerollBuf);
	
	// free sourceName
	if(node->sourceName)
		free(node->sourceName);
	// free rsp sessions
	if(node->rsp)
		rspSessionFree(node->rsp);
	if(node->recode_rsp)
		rspSessionFree(node->recode_rsp);
	// free track list
	if(node->trackList)
		cJSON_Delete(node->trackList);
	if(node->rspStream)
		cJSON_Delete(node->rspStream);
	// record locks are ignored... It is assumed that this source record
	// and it's children are not being used any longer by other threads
	current = node->listHead;
	while(prev = current){
		current = prev->link;
		freeListenerNode(prev, log);
	}
	if(node->tc_socket > -1){
		shutdown(node->tc_socket, SHUT_RDWR);
		close(node->tc_socket);
	}
	if(node->child){
		int stat;
		killpg(node->child, SIGKILL);
		waitpid(node->child, &stat, 0);
	}
	pthread_mutex_destroy(&node->lock);
	pthread_mutex_destroy(&node->trackLock);
	free(node);
}

void removeStaticListener(cJSON *listener, struct serverContext *cPtr, struct listenerNode *head)
{
	// remove static unicast or multicast item
	cJSON *item;
	unsigned short portNo;
	struct listenerNode *node;
	unsigned char type;
	
	portNo = 0;

	if((item = cJSON_GetObjectItem(listener, "Type")) && item->valuestring){
		if(strcmp(item->valuestring, "IP6") == 0)
			type = 1;
		else if(strcmp(item->valuestring, "IP4") == 0)
			type = 0;
		else{
			fprintf(stderr, "Unknown static listener specified.  Must specify either IP4 or IP6.\n");
			return;	
		}	
	}else{
		// IP type not specified: assume IPv4
		type = 0;
	}
	
	if(item = cJSON_GetObjectItem(listener, "Port"))
		portNo = item->valueint;						
	if(portNo && (item = cJSON_GetObjectItem(listener, "Address"))){
		if((item->valuestring == NULL) || (strlen(item->valuestring) == 0))
			portNo = 0;
	}
	if(portNo){
		struct sockaddr_in6 sockAddr;
		struct sockaddr_in6 *addrPtr;
		if(addrPtr = setSockAddr(&sockAddr, type, portNo, item->valuestring)){			
			struct recvrRecord rr;
			
			bzero(&rr, sizeof(struct recvrRecord));
			rr.apparentAddress = *addrPtr;
			rr.relay = 0;	// this is not a listener requested relay
			
			if(node = findListenerNode(&rr, head)){
				if(node->keep){
					// found existing record in relaying list marked as static... remove it
					pthread_mutex_unlock(&node->lock);
					unlinkNode(node, head, 0);
					freeListenerNode(node, cPtr->log_listeners);
				}
			}			
		}
	}	
}


void addStaticListener(cJSON *listener, struct serverContext *cPtr, struct listenerNode *head, struct sourceRecord *sPtr)
{
	// add static unicast or multicast item
	cJSON *item;
	unsigned char ttl;
	unsigned short portNo;
	struct listenerNode *nPtr;
	unsigned char type;
	
	portNo = 0;
	ttl = 0;
		
	if((item = cJSON_GetObjectItem(listener, "Type")) && item->valuestring){
		if(strcmp(item->valuestring, "IP6") == 0)
			type = 1;
		else if(strcmp(item->valuestring, "IP4") == 0)
			type = 0;
		else{
			fprintf(stderr, "Unknown static listener specified.  Must specify either IP4 or IP6.\n");
			return;	
		}	
	}else{
		// IP type not specified: assume IPv4
		type = 0;
	}
	
	if(item = cJSON_GetObjectItem(listener, "MulticastTTL"))
		ttl = item->valueint;
	if(item = cJSON_GetObjectItem(listener, "Port"))
		portNo = item->valueint;						
	if(portNo && (item = cJSON_GetObjectItem(listener, "Address"))){
		if((item->valuestring == NULL) || (strlen(item->valuestring) == 0))
			portNo = 0;
	}
	if(portNo){
		struct sockaddr_in6 sockAddr;
		struct sockaddr_in6 *addrPtr;
		if(type == 1){			
			if(cPtr->svr_socket6 == -1){
				fprintf(stderr, "Failed to add static IPv6 listener %s on port %u: IPv6 not initialized.\n", item->valuestring, portNo);
				return;
			}
			addrPtr = setSockAddr(&sockAddr, TRUE, portNo, item->valuestring);
		}else{
			if(cPtr->svr_socket4 == -1){
				fprintf(stderr, "Failed to add static IPv4 listener %s on port %u: IPv4 not initialized.\n", item->valuestring, portNo);
				return;
			}
			addrPtr = setSockAddr(&sockAddr, FALSE, portNo, item->valuestring);
		}
		if(addrPtr){
			nPtr = newListenerNode(cPtr, NULL);	
			bzero(&(nPtr->rr), sizeof(struct recvrRecord));
			nPtr->authBlock = 0;
			if(item = cJSON_GetObjectItem(listener, "NoAuth")){
				if(item->type == cJSON_True)
					nPtr->authBlock = 1;
				if(item->type == cJSON_False)
					nPtr->authBlock = 0;
				if(item->type == cJSON_Number){
					if(item->valueint)
						nPtr->authBlock = 1;
					else
						nPtr->authBlock = 0;
				}
			}
			nPtr->rr.apparentAddress = *addrPtr;
			nPtr->rr.relay = 0;	// this is not a listener requested relay
			nPtr->keep = TRUE;	// however, we will be relaying to this listener on the pre-determined port and address
			nPtr->hash = ELFHash(0, (char *)&(nPtr->rr.apparentAddress), sizeof(struct sockaddr_in6));
			if(nPtr->rr.via)
				nPtr->hash = ELFHash(nPtr->hash, nPtr->rr.via, strlen(nPtr->rr.via));
			if(ttl){
				// create a multicast socket
				if(nPtr->socket = multicastSocketSetup(cPtr, ttl) < 0){
					// socket failure
					freeListenerNode(nPtr, FALSE);
					fprintf(stderr, "Failed to add static listener %s on port %u: Socket failure.\n", item->valuestring, portNo);
					return;
				}
			}
			if(linkListenerNode(head, nPtr, sPtr, cPtr->log_listeners) == NULL){
				fprintf(stderr, "Failed to add static listener %s on port %u: relay limit exceeded\n", item->valuestring, portNo);
				freeListenerNode(nPtr, FALSE);
			}
			return;
		}
	}
	if(item && item->valuestring)
		fprintf(stderr, "Failed to add static listener %s on port %u: bad address or port number.\n", item->valuestring, portNo);
	else 
		fprintf(stderr, "Failed to add unknown static listener on port %u: bad address or port number.\n", portNo);

}

struct sourceRecord *initSourceNode(struct sourceRecord *rec, struct serverContext *cPtr, cJSON *settings)
{
	// rec, if not NULL, must be locked on entry
	// returns NULL on failure, the passed rec is not freed
	// returns record pointer rec on sucess, when the existing record data was modified or initialized.
	// returns a different record pointer than rec if new record had to be allocated, or rec was NULL:  
	// The new record will be unlinked, and the old record, if any, is left unmodifed by this function.
	
	struct sourceRecord *newrec;
	cJSON *item, *uc_list, *child;
	cJSON *old_rsp, *new_rsp;
	cJSON *old;
	cJSON *sconf;
	cJSON *rspCurrent;
	FILE *confFile;
	unsigned int len;
	unsigned char err;
	
	newrec = NULL;
	if(settings == NULL)
		return NULL;
	if(rec == NULL){
		newrec = newSourceNode(cPtr);
		rec = newrec;
	}
	// compare new settings to old, if any old settings exist
	if(rec->source_conf){
		if(rec->tc_socket == -2)
			// the re-coder is broken... don't attempt to modify old record
			goto fail;
		
		// this record is already configured... see if we need to change it, or possibly create a whole new record
		
		// verify the name is the same
		if(((item = cJSON_GetObjectItem(settings, "Name")) == NULL) || ((old = cJSON_GetObjectItem(rec->source_conf, "Name")) == NULL))
			goto fail;
		if((item->valuestring == NULL) || (old->valuestring == NULL) || strcmp(item->valuestring, old->valuestring))
			goto fail;
		
		// set the new relay listener limit and pre-rool pace values with out checking the old value
		if((item = cJSON_GetObjectItem(settings, "relayLimit")) == NULL)
			goto fail; 
		rec->relay_limit = item->valueint;

		if(item = cJSON_GetObjectItem(settings, "preRollPace"))
			rec->prerollPace = item->valueint;
		else
			rec->prerollPace = 0;
		
		// check for specified bind addresss
		if(item = cJSON_GetObjectItem(settings, "Bind"))
			if(item->valuestring == NULL)
				item = NULL;
		if(old = cJSON_GetObjectItem(rec->source_conf, "Bind"))
			if(old->valuestring == NULL)
				old = NULL;
		if((!item && old) || (item && !old) || (item && old && strcmp(item->valuestring, old->valuestring)))
			goto fail; 
		
		// check for source config file and settings changes
		if(((item = cJSON_GetObjectItem(settings, "File")) == NULL) || (item->valuestring == NULL) || (strlen(item->valuestring) == 0)){
			if((sconf = cJSON_GetObjectItem(settings, "rspStream")) == NULL){
				fprintf(stderr, "The new source [%s] configuration file or rspStream settings were not specified.\n", rec->sourceName);
				syslog(LOG_WARNING, "The new source [%s] configuration file or rspStream settings were not specified.", rec->sourceName);
				goto fail; 
			}
			if(!compareItems(sconf, rec->rspStream, NULL)){
				goto fail; 
			}
			// Need to do this by reference since rspCurrent can be freed and sconf a member of the settings object			
			if(rec->rspStream)
				cJSON_Delete(rec->rspStream);
			if(item = create_reference(sconf)){
				if(sconf->string)
					item->string=cJSON_strdup(sconf->string);
			}
			rec->rspStream = item;
		}else{
			confFile = fopen(item->valuestring, "r");		
			if(confFile == NULL){
				fprintf(stderr, "Failed to open the new source [%s] configuration file:%s.\n", rec->sourceName, item->valuestring);
				syslog(LOG_WARNING, "Failed to open the new source [%s] configuration file:%s.", rec->sourceName, item->valuestring);
				goto fail; 
			}
			sconf = rspSessionReadConfigFile(confFile);
			fclose(confFile);
			if(sconf == NULL){
				fprintf(stderr, "New source [%s] configuration file:%s is not jSON format.\n", rec->sourceName, item->valuestring);
				syslog(LOG_WARNING, "New source [%s] configuration file:%s is not jSON format.", rec->sourceName, item->valuestring);
				goto fail; 
			}
			// Compare source config file settings to the old source rsp session
			if(!compareItems(sconf, rec->rspStream, NULL)){
				cJSON_Delete(sconf);
				goto fail; 
			}
			// keep old
			cJSON_Delete(sconf);
		}
		   		   
		// check for rsp section
		new_rsp = cJSON_GetObjectItem(settings, "rsp");
		old_rsp = cJSON_GetObjectItem(rec->source_conf, "rsp");
		if((new_rsp && !old_rsp) || (!new_rsp && old_rsp))
			goto fail; 
		   
		if(new_rsp && old_rsp){
			// Both are present: check reformat section
			item = cJSON_GetObjectItem(new_rsp, "reformat");
			old = cJSON_GetObjectItem(old_rsp, "reformat");
			if((item && !old) || (!item && old))
				goto fail; 
			if(item && old){
				if(!compareItems(item, old, NULL))
					goto fail; 
			}
			
			// and check for source authorization packet relay supression
			if(item = cJSON_GetObjectItem(new_rsp, "NoAuth")){
				if(item->type == cJSON_True)
					rec->authBlock = 1;
				if(item->type == cJSON_False)
					rec->authBlock = 0;
				if(item->type == cJSON_Number){
					if(item->valueint)
						rec->authBlock = 1;
					else
						rec->authBlock = 0;
				}
			}
			
			// and check for new statically assigned unicast relay listeners
			if(uc_list = cJSON_GetObjectItem(new_rsp, "staticListeners")){
				child = uc_list->child;
				uc_list = cJSON_GetObjectItem(old_rsp, "staticListeners");
				while(uc_list && child){
					if(findMatchingItemInArray(child, uc_list, NULL) == -1){
						// item not already in uc list... add it.
						addStaticListener(child, cPtr, rec->listHead, rec);
					}
					child = child->next;
				}
			}
				  
			// and remove old statically assigned unicast relay listeners
			if(uc_list = cJSON_GetObjectItem(old_rsp, "staticListeners")){
				child = uc_list->child;
				uc_list = cJSON_GetObjectItem(new_rsp, "staticListeners");
				while(uc_list && child){
					if(findMatchingItemInArray(child, uc_list, NULL) == -1){
						// item not in new uc list... remove it if it's in the list
						removeStaticListener(child, cPtr, rec->listHead);
					}
					child = child->next;
				}
			}		
		}		   
		
		// either unmodified or slightly modified: save settings and return no error
		rec->source_conf = settings;
		
		unsigned int size = 0;
		if(rec->sc_conf = cJSON_GetObjectItem(settings, "shoutcast")){
			// check for changes to sc pre-roll
			if(item = cJSON_GetObjectItem(rec->sc_conf, "preRollKByte"))
				size = item->valueint * 1024;
		}
		if(size == 0)
			// default preroll size is 64KiBytes
			size = 64 * 1024;
		
		if(size != rec->sc_prerollSize){
			if(rec->sc_prerollBuf){
				free(rec->sc_prerollBuf);
				rec->sc_prerollBuf = NULL;
			}
			// we make the buffer twice the desired size so we can catch send underruns without rolling over
			if(size && (rec->sc_prerollBuf = (unsigned char *)malloc(size * 2)))
				rec->sc_prerollSize = size;
			else
				rec->sc_prerollSize = 0;
			rec->sc_prerollFill = FALSE;
		}		
		if(item = cJSON_GetObjectItem(rec->sc_conf, "underrunLimit")){
			if((item->valueint < 0) || (item->valueint > 100))
				item->valueint = 50;
			rec->sc_underrun_limit = item->valueint;
		}else
			rec->sc_underrun_limit = 50;
		
		rec->rsp_conf = cJSON_GetObjectItem(settings, "rsp");
		if(rec->rsp_conf){
			// even though there was no change, we need to update the meta_exclude pointer to point to the new
			// cJSON structue... the old one will be freed shortly, so we can't reference it any longer.
			if(item = cJSON_GetObjectItem(rec->rsp_conf, "reformat"))
				rec->meta_exclude = cJSON_GetObjectItem(item, "meta-exclude");		
		}			
		return rec;		   
	}
			   
	if(newrec){
		// Setting up a new record, first save our settings for reference
		rec->source_conf = settings;
		
		// create a jSON array for track history
		rec->trackList = cJSON_CreateArray();
		
		// Set up name and relay count limit
		if((item = cJSON_GetObjectItem(settings, "Name")) == NULL)
			goto fail;
		if((item->valuestring == NULL) || ((len = strlen(item->valuestring)) == 0))
			goto fail;
		rec->sourceName = (char *)calloc(1, len + 1);
		strcpy(rec->sourceName, item->valuestring);
		
		if((item = cJSON_GetObjectItem(settings, "relayLimit")) == NULL)
			goto fail; 
		rec->relay_limit = item->valueint;
		
		if(item = cJSON_GetObjectItem(settings, "preRollPace"))
			rec->prerollPace = item->valueint;
		else
			rec->prerollPace = 0;

		// create new RSP source session 
		rec->rsp = rspSessionNew(clientID);
		
		// configure source rsp session from the specified source config file
		if((item = cJSON_GetObjectItem(settings, "File")) && item->valuestring && strlen(item->valuestring)){
			confFile = fopen(item->valuestring, "r");		
			if(confFile == NULL){
				fprintf(stderr, "Failed to open the source [%s] configuration file:%s.\n", rec->sourceName, item->valuestring);
				syslog(LOG_WARNING, "Failed to open the source [%s] configuration file:%s.", rec->sourceName, item->valuestring);
				goto fail; 
			}
			if(sconf = rspSessionReadConfigFile(confFile)){
				rspCurrent = sconf;
				while(((err = rspSessionConfigNextJSON(rec->rsp, &rspCurrent)) != RSP_ERROR_NONE) && (err != RSP_ERROR_END));
				if(err == RSP_ERROR_END){
					cJSON_Delete(sconf);
					fclose(confFile);
					fprintf(stderr, "Failed to configure the source [%s] from configuration file:%s.\n", rec->sourceName, item->valuestring);
					syslog(LOG_WARNING, "Failed to configure the source [%s] from configuration file:%s.", rec->sourceName, item->valuestring);
					goto fail; 
				}
				if(rspCurrent){
					fprintf(stderr, "Only the first valid rspStream entry for source [%s] will be used.\n", rec->sourceName);
					syslog(LOG_WARNING, "Only the first valid rspStream entry for source [%s] will be used.", rec->sourceName);
				}
			}else{
				fclose(confFile);
				fprintf(stderr, "Failed to configure the source [%s] from configuration file:%s.\n", rec->sourceName, item->valuestring);
				syslog(LOG_WARNING, "Failed to configure the source [%s] from configuration file:%s.", rec->sourceName, item->valuestring);
				goto fail; 
			}
			fclose(confFile);
			rec->rspStream = sconf;
		}else{
			if((sconf = cJSON_GetObjectItem(settings, "rspStream")) == NULL){
				fprintf(stderr, "The new source [%s] configuration file or rspStream settings were not specified.\n", rec->sourceName);
				syslog(LOG_WARNING, "The new source [%s] configuration file or rspStream settings were not specified.", rec->sourceName);
				goto fail; 
			}	
			rspCurrent = sconf;
			while(((err = rspSessionConfigNextJSON(rec->rsp, &rspCurrent)) != RSP_ERROR_NONE) && (err != RSP_ERROR_END));
			if(err == RSP_ERROR_END){
				fprintf(stderr, "Failed to configure the source [%s] from the specified rspStream settings.\n", rec->sourceName);
				syslog(LOG_WARNING, "Failed to configure the source [%s] from the specified rspStream settings.", rec->sourceName);
				goto fail; 
			}
			if(rspCurrent){
				fprintf(stderr, "Only the first valid rspStream entry for source [%s] will be used.\n", rec->sourceName);
				syslog(LOG_WARNING, "Only the first valid rspStream entry for source [%s] will be used.", rec->sourceName);
			}			
			// Need to do this by reference since rspCurrent can be freed and sconf a member of the settings object	
			if(item = create_reference(sconf)){
				if(sconf->string)
					item->string=cJSON_strdup(sconf->string);
			}
			rec->rspStream = item;
		}
		rspSessionClear(rec->rsp, TRUE);
		// set up source network socket using the RSP library
		char *rsp_bind = NULL;
		if(item = cJSON_GetObjectItem(settings, "Bind")){
			if(item->valuestring && strlen(item->valuestring))
				rsp_bind = item->valuestring;
		}
		
		// set up Network socket and address records, socket blocking time out set to 10 seconds
		// note:  We only try once... there is no loop to see if the returned source/session is actually sending packets
		if(rspSessionNextNetworkSetup(rec->rsp, 10, rsp_bind) != RSP_ERROR_NONE){
			fprintf(stderr, "Failed to initialize the network for source [%s].\n", rec->sourceName);
			syslog(LOG_WARNING, "Failed to initialize the network for source [%s].", rec->sourceName);
			goto fail; 
		}
		// save shoutcast settings, if any.  These will be read by the relay thread, if needed.				
		unsigned int size = 0;
		if(rec->sc_conf = cJSON_GetObjectItem(settings, "shoutcast")){
			// check for changes to sc pre-roll
			if(item = cJSON_GetObjectItem(rec->sc_conf, "preRollKByte"))
				size = item->valueint * 1024;
		}
		if(size == 0)
			// default preroll size is 64 kiBytes
			size = 64 * 1024;
		
		// we make the buffer twice the desired size so we can catch send underruns without rolling over
		if(rec->sc_prerollBuf = (unsigned char *)malloc(size * 2))
			rec->sc_prerollSize = size;
		else
			rec->sc_prerollSize = 0;
		rec->sc_prerollFill = FALSE;

		if(item = cJSON_GetObjectItem(rec->sc_conf, "underrunLimit")){
			if((item->valueint < 0) || (item->valueint > 100))
				item->valueint = 50;
			rec->sc_underrun_limit = item->valueint;
		}else
			rec->sc_underrun_limit = 50;
		
		// save rsp relay settings, if any
		if(rec->rsp_conf = cJSON_GetObjectItem(settings, "rsp")){
			// set up re-formating of out going relay stream, if specified
			if(item = cJSON_GetObjectItem(rec->rsp_conf, "reformat")){

				recodeRelaySetup(rec, item);
				if(rec->recode_rsp == NULL){
					fprintf(stderr, "Failed to setup RSP re-formating for source [%s].\n", rec->sourceName);
					syslog(LOG_WARNING, "Failed to setup RSP re-formating for source [%s].", rec->sourceName);
					goto fail; 
				}
				rec->meta_exclude = cJSON_GetObjectItem(item, "meta-exclude");		
				if(item = cJSON_GetObjectItem(item, "re-encode")){
					if(!transcoderExecute(rec, item)){
						fprintf(stderr, "Failed to setup RSP re-encoding for source [%s].\n", rec->sourceName);
						syslog(LOG_WARNING, "Failed to setup RSP re-encoding for source [%s].", rec->sourceName);
						goto fail; 						
					}
				}
			}
			// and check for source authorization packet relay supression
			if(item = cJSON_GetObjectItem(rec->rsp_conf, "NoAuth")){
				if(item->type == cJSON_True)
					rec->authBlock = 1;
				if(item->type == cJSON_False)
					rec->authBlock = 0;
				if(item->type == cJSON_Number){
					if(item->valueint)
						rec->authBlock = 1;
					else
						rec->authBlock = 0;
				}
			}
		
			// look for preset unicast relay destinations to add to the listener list
			if(uc_list = cJSON_GetObjectItem(rec->rsp_conf, "staticListeners")){
				if(child = uc_list->child){
					while(child){
						addStaticListener(child, cPtr, rec->listHead, rec);
						child = child->next;
					}
				}
			}
		}
		if(rec->rsp->reportToSource == FALSE){
			// send a request to relay server or receiver report host to start sending stream packets... direct source will ignore this request
			if(rspPacketRecvrRequestSend(rec->rsp, NULL, RSP_RR_START) != RSP_ERROR_NONE){
				fprintf(stderr, "Failed to send start request for source [%s].\n", rec->sourceName);
				syslog(LOG_WARNING, "Failed to send start request for source [%s].", rec->sourceName);
				goto fail; 
			}
		}
		// start relay thread
		if(startSourceRelayTask(cPtr, rec)){
			fprintf(stderr, "Failed to start relay thread for source [%s].\n", rec->sourceName);
			syslog(LOG_WARNING, "Failed to start relay thread for source [%s].", rec->sourceName);
			goto fail; 
		}
	}
	// return no error
	return rec;
	
fail:
	// if we have alocated a new record in the process, free it.
	if(newrec)
		freeSourceNode(newrec, cPtr->log_listeners);
	// return error
	return NULL;
}

struct sourceRecord *getSourceByName(const char *name, struct sourceRecord *head)
{
	// if found, the node is returned in the locked state.
	// Do not hold the lock for long!
	struct sourceRecord	*prev, *current; 
	
	prev = head;
	pthread_mutex_lock(&prev->lock); 
	while((current = prev->next) != NULL){ 
		pthread_mutex_lock(&current->lock); 
		if(current->sourceName && (strcasecmp(name, current->sourceName) == 0)){
			pthread_mutex_unlock(&prev->lock);
			return current;
		}
		pthread_mutex_unlock(&prev->lock);
		prev = current; 
	} 
    pthread_mutex_unlock(&prev->lock); 
    return NULL; 
}

void *reportTask(void* refCon)
{
	struct threadPass *tp;
	struct serverContext *cPtr;
	struct recvrRecord rr;
	struct sockaddr_in6 from;
	unsigned int usize;
	int size;
	int *sock;
	unsigned char col, blk, flags;
	unsigned short psize;
	unsigned char rr_packet[277];	
	struct listenerNode *node;
	char *str;
	
	tp = (struct threadPass *)refCon;
	cPtr = tp->cPtr;
	sock = tp->sockPtr;
	// signal the parent we are done with the structure pointer that was passed
	tp->sockPtr = NULL;
	while(cPtr->run && (*sock > -1)){
		usize = sizeof(struct sockaddr_in6);
		bzero(&from, usize);
		bzero(&rr.statedAddress, usize);
		size = recvfrom(*sock, rr_packet, sizeof rr_packet, 0, (struct sockaddr *)&from, &usize);	
		if(size > 0){
			if(rspPacketReadHeader(rr_packet, size, &flags, &psize, &col, &blk, NULL, NULL, cPtr->rep_rsp->crc_table) == RSP_ERROR_RRPCKT){
				if(rspPacketRecvrReportRequestGet(rr_packet, &from, &rr) == RSP_ERROR_NONE){
					// we have a valid listener report/request packet... process it!
					if(cPtr->relay_identity && (rr.via == NULL)){
						cJSON *group;
						char ipStr[49];
						struct sockaddr_in *addr;
						
						// if this is a report from someone we are either relaying or a report we are first to collect
						// and then forwarding forwarding, modify the record to indicate relaying or first collected via us
						
						// Modify the local rr.meta jSON record to reflect a via record and set the stated address 
						// field to the apparent address, as seen by us
						group = NULL;
						if(group = cJSON_GetObjectItem(rr.meta, "IP6")){
							cJSON_DeleteItemFromObject(group, "Port");
							cJSON_AddNumberToObject(group, "Port", htons(rr.apparentAddress.sin6_port));
							if(inet_ntop(AF_INET6, &rr.apparentAddress.sin6_addr, ipStr, sizeof(ipStr))){
								cJSON_DeleteItemFromObject(group, "Addr");
								cJSON_AddStringToObject(group, "Addr", ipStr);
							}
						}else if(group = cJSON_GetObjectItem(rr.meta, "IP4")){
							addr = (struct sockaddr_in *)&rr.apparentAddress;
							cJSON_DeleteItemFromObject(group, "Port");
							cJSON_AddNumberToObject(group, "Port", ntohs(addr->sin_port));
							if(inet_ntop(AF_INET, &(addr->sin_addr), ipStr, sizeof(ipStr))){
								cJSON_DeleteItemFromObject(group, "Addr");
								cJSON_AddStringToObject(group, "Addr", ipStr);
							}
						}
						if(group){
							cJSON_DeleteItemFromObject(group, "Relay");
							cJSON_AddStringToObject(group, "Via", cPtr->relay_identity);
						}
					}	
					node = NULL;
					struct sourceRecord *rec;
					cJSON *item;
					struct listenerNode	*head;
					
					rec = NULL;
					if((item = cJSON_GetObjectItem(rr.meta, "Stream")) && item->valuestring && strlen(item->valuestring))
						rec = getSourceByName(item->valuestring, cPtr->sourceList);					
					if(rec)
						head = rec->listHead;	// matching source 
					else 
						head = cPtr->listHead;	// no matching source
					
					if(node = findListenerNode(&rr, head)){
						// found existing record is non-relaying list
						if(rr.start_stop_request < 0){
							// stop request: delete record
							if(!node->keep){
								pthread_mutex_unlock(&node->lock);
								unlinkNode(node, head, 0);
								freeListenerNode(node, cPtr->log_listeners);
							}else
								pthread_mutex_unlock(&node->lock);
						}else if(rr.start_stop_request > 0){
							// start request... just update the last heard time since it is already listed
							node->rr.lastHeard = rr.lastHeard;
							pthread_mutex_unlock(&node->lock);
						}else{
							// new report: update record
							rspRecvrReportFree(&node->rr);
							// set record to new report							
							node->rr = rr;
							pthread_mutex_unlock(&node->lock);
						}
					}else{
						// still not found... new record
						node = newListenerNode(cPtr, &rr);
						if(linkListenerNode(head, node, rec, cPtr->log_listeners) == NULL){
							// no more room for addtional listeners
							cJSON *data;
							char *data_str;
							unsigned int size;
							
							if(data = cJSON_CreateObject()){
								if(cPtr->rep_rsp->clientName){
									cJSON_AddStringToObject(data, "Server", cPtr->rep_rsp->clientName);
									cJSON_AddStringToObject(data, "error", "Server full");
									if(data_str = cJSON_PrintUnformatted(data)){
										// format packet and send
										size = strlen(data_str) + 1;
										if((size > 0) && (size <= 240)){
											if(size % 16)
												size = size + 16;
											size = (size / 16) * 16;
											bzero(rr_packet, size + 1);
											rr_packet[0] = RSP_FLAG_RR | ((size - 16) & 0xF0);
											memcpy(rr_packet + 1, data_str, strlen(data_str));
											size = size + 1;
											contextSendTo(cPtr, rr_packet, size+1, (struct sockaddr*)&rr.apparentAddress);
										}
										free(data_str);
									}
								}
								cJSON_Delete(data);
							}
							freeListenerNode(node, FALSE);
							if(cPtr->log_listeners && node->rr.meta && (str = cJSON_PrintUnformatted(node->rr.meta))){
								syslog(LOG_INFO, "Maximum relay listeners exceeded [info=%s]", str);
								free(str);
							}
						}
					}
					if(rec)
						pthread_mutex_unlock(&rec->lock); 
					
					if(cPtr->forwardAddress.sin6_family && (rr.relay < 2)){
						// we only forward reports from cluster listneres from the first relay in the cluster
						char *data_str;
						
						if(data_str = cJSON_PrintUnformatted(rr.meta)){
							// format packet and send
							size = strlen(data_str) + 1;
							if((size > 0) && (size <= 240)){
								if(size % 16)
									size = size + 16;
								size = (size / 16) * 16;
								bzero(rr_packet, size + 1);
								rr_packet[0] = RSP_FLAG_RR | ((size - 16) & 0xF0);
								memcpy(rr_packet + 1, data_str, strlen(data_str));
								pthread_mutex_lock(&cPtr->lock);
								contextSendTo(cPtr, rr_packet, size+1, (struct sockaddr*)&cPtr->forwardAddress);
								pthread_mutex_unlock(&cPtr->lock);
							}
							free(data_str);
						}
					}
				}
			}
		}
		// check for old non-source record timeouts, note peak listeners
		checkListenerTimeout(cPtr, cPtr->listHead, NULL);
	}
	pthread_exit(0);
}

char *pls_content(int sock, char *stream_name, struct sourceRecord *head)
{
	char *out;
	struct sockaddr_in6 addr;
	struct sockaddr_in *addr4;
	struct sourceRecord *rec;
	socklen_t len;
	unsigned short portNo;
	char ipStr[49];
	char buffer[64];
	
	if(stream_name == NULL)
		return NULL;
	
	len = sizeof(addr);
	bzero(&addr, sizeof(addr));
	if(getsockname(sock, (struct sockaddr *)&addr, &len) == -1)
		return NULL;
	// get the ip address the request connection came in on
	if(addr.sin6_family == AF_INET){
		addr4 = (struct sockaddr_in *)&addr;
		if(!inet_ntop(AF_INET, &(addr4->sin_addr), ipStr, sizeof(ipStr)))
			return NULL;
		
	}else if(addr.sin6_family == AF_INET6){
		if(!inet_ntop(AF_INET6, &(addr.sin6_addr), ipStr, sizeof(ipStr)))
			return NULL;
	}else 
		return NULL;

	portNo = ntohs(addr.sin6_port);
	
	out = NULL;
	if(rec = getSourceByName(stream_name, head)){
		pthread_mutex_unlock(&rec->lock); 
		// associated stream does exist
		appendstr(&out, "[playlist]\r\n");
		appendstr(&out, "NumberOfEntries=1\r\n");
		appendstr(&out, "File1=http://");
		if(addr.sin6_family == AF_INET6)
			snprintf(buffer, sizeof(buffer), "[%s]:%u/", ipStr, portNo);
		else
			snprintf(buffer, sizeof(buffer), "%s:%u/", ipStr, portNo);
		appendstr(&out, buffer);
		appendstr(&out, stream_name);
		appendstr(&out, "\r\n");
		appendstr(&out, "Length1=-1\r\n");
		appendstr(&out, "Version=2\r\n\r\n");		
	}
	return out;
}

char *listen_content(int sock, struct sourceRecord *head)
{
	char *out;
	struct sockaddr_in6 addr;
	struct sockaddr_in *addr4;
	socklen_t len;
	char ipStr[49], buf[256];
	struct sourceRecord *prev_s, *cur_s;
	char *enc_uri, *link;
	cJSON *item;	
	unsigned short portNo;
	
	out = NULL;
	len = sizeof(addr);
	bzero(&addr, sizeof(addr));
	if(getsockname(sock, (struct sockaddr *)&addr, &len) == -1)
		return NULL;
	// get the ip address the request connection came in on
	if(addr.sin6_family == AF_INET){
		addr4 = (struct sockaddr_in *)&addr;
		if(!inet_ntop(AF_INET, &(addr4->sin_addr), ipStr, sizeof(ipStr)))
			return NULL;

	}else if(addr.sin6_family == AF_INET6){
		if(!inet_ntop(AF_INET6, &(addr.sin6_addr), ipStr, sizeof(ipStr)))
			return NULL;
	}else 
		return NULL;

	portNo = ntohs(addr.sin6_port);

	appendstr(&out, "<html>\n<head><title>Hosted Streams</title></head>\n<body>\n<center>\n");
	appendstr(&out, "<h2>");
	appendstr(&out, " Shoutcast Compatible Interface</h2>\n");

	// travers source list
	prev_s = head;
	pthread_mutex_lock(&prev_s->lock); 
	if(prev_s->next == NULL){
		snprintf(buf, sizeof buf, "<h3>Hosted Streams: NONE</h3>\n");
	}else{
		appendstr(&out, "<h3>Hosted Streams (click link to listen):</h3>\n");
		appendstr(&out, "<table cellpadding=5>\n");
		while(cur_s = prev_s->next){ 
			pthread_mutex_lock(&cur_s->lock); 
			pthread_mutex_unlock(&prev_s->lock);
			if(cur_s->sourceName){
				if(item = cJSON_GetObjectItem(cur_s->sc_conf, "public")){
					if(item->valueint){
						if(enc_uri = encodeURI(cur_s->sourceName)){
							if(cur_s->sourceStatus && (cur_s->tc_socket > -2)){
								link = (char *)malloc(71);
								if(addr.sin6_family == AF_INET6)
									snprintf(link, 71, "http://[%s]:%u/", ipStr, portNo);
								else
									snprintf(link, 71, "http://%s:%u/", ipStr, portNo);
								appendstr(&link, enc_uri);
								free(enc_uri);
								snprintf(buf, sizeof buf, "<tr><td><A HREF='%s.pls'>%s</A></td><td>Up with %.1f of %u listeners</td></tr>\n", link, cur_s->sourceName, cur_s->relay_count, cur_s->relay_limit);
								free(link);
							}else{
								snprintf(buf, sizeof buf, "<tr><td>%s</td><td>Down</td></tr>\n", cur_s->sourceName);
							}
							appendstr(&out, buf);
						}
					}
				}
			}
			prev_s = cur_s;
		}
		appendstr(&out, "</table>\n");
	}
	pthread_mutex_unlock(&prev_s->lock);
	appendstr(&out, "<HR>");
	appendstr(&out, clientID);
	appendstr(&out, " &#169 Ethan Funk 2012-2020<HR></center>\n</body>\n</html>\n");
	return out;
}

void sendHttpContent(int sock, char *type, const char *content)
{
	time_t t_now;
	struct tm brokentime;
	char buffer[256];
	char *out;
	
	if(content == NULL)
		return;
	
	out = NULL;
	appendstr(&out, "HTTP/1.1 200 OK\r\n");
	t_now = time(NULL);
	gmtime_r(&t_now, &brokentime);
	strftime(buffer, sizeof(buffer), "%a, %d %b %y %H:%M:%S %Z", &brokentime);
	appendstr(&out, "Date: ");
	appendstr(&out, buffer);
	appendstr(&out, "\r\n");
	
	appendstr(&out, "Server: ");
	appendstr(&out, clientID);
	appendstr(&out, "\r\n");
		
	appendstr(&out, "Content-Type: ");
	appendstr(&out, type);
	appendstr(&out, "\r\n");
	
	snprintf(buffer, sizeof(buffer), "%u\r\n\r\n", (unsigned int)strlen(content));
	appendstr(&out, "Content-Length: ");
	appendstr(&out, buffer);
	
	appendstr(&out, content);
	
	write(sock, out, strlen(out));
	close(sock);
	free(out);
	return;
}

void *shoutcastSession(void* refCon)
{		
	struct threadPass *tp;
	struct serverContext *cPtr;
	struct sourceRecord *rec;
	struct sockaddr_in6 addr;
	struct recvrRecord rr;	
	cJSON *group, *item;
	cJSON *data, *ipGrp, *rep;
	char ipStr[49];
	struct sockaddr_in *addr4;
	struct timeval timeout;
	struct listenerNode *node;
	int sock;
	int val;
	int to_sec;
	char buffer[256];
	char *in, *out, *line, *savePtr;
	int nbytes;	
	char *str;
	char *errMsg;
	char *httpv;
	char *agent;
	char *uri, *raw_uri;
	char *key;
	char *value;
	char *content;
	unsigned char metaFlag;
	
	errMsg = NULL;
	uri = NULL;
	agent = NULL;
	httpv = NULL;
	metaFlag = 0;
	node = NULL;
	rep = NULL;
	ipGrp = NULL;
	data = NULL;
	in = NULL;
	rec = NULL;
	raw_uri = NULL;
	
	tp = (struct threadPass *)refCon;
	cPtr = tp->cPtr;
	sock = tp->sock;
	addr = tp->addr;
	// signal the parent we are done with the structure pointer that was passed
	tp->sock = -1;

	// set up socket timeout options	
	to_sec = cPtr->sc_sock_timeout;
	if(to_sec == 0)
		to_sec = 30;
	timeout.tv_sec = to_sec;		// seconds
	timeout.tv_usec = 0;		    // and microseconds
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));	
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));	
	
	// Get request
	while((nbytes = read(sock, buffer, sizeof(buffer)-1)) > 0){
		buffer[nbytes] = 0;			// null terminate the buffer
		appendstr(&in, buffer);		// add buffer to request string collected so far
		if(strstr(in, "\r\n\r\n"))	// see if the request contains a pair of CR LF charactors, indicating end of the request. 
			break;
		if(strlen(in) > 4096){
			// don't accept requests larger than 4kiB
			errMsg = "413 Request Entity Too Large";
			goto fail;
		}
	}
	if(in && (nbytes > 0)){
		// process request
		savePtr = in;
		while(line = strtok_r(NULL, "\r\n", &savePtr)){
			if(strlen(line)){
				if(strstr(in, "GET /") == line){
					// we have a GET request, extract URI and HTTP version
					strtok_r(line, " ", &httpv);
					raw_uri = strtok_r(NULL, " ", &httpv);
				}else{
					if((key = strtok_r(line, ":", &value)) && value){
						if((strcasecmp(key, "User-agent") == 0) && *value){
							agent = value + 1;
							agent = strtok_r(agent, " \t", &value);
						}else if(strcasecmp(key, "icy-metadata") == 0)
							metaFlag = atoi(value);				
					}
					// we don't care about other header fields, so we just ignore them
				}
			}
		}
		if(raw_uri && httpv && ((strcasecmp(httpv, "HTTP/1.1") == 0) || (strcasecmp(httpv, "HTTP/1.0") == 0)) ){
			// uri, if not NULL after this call, needs to be freed when your done with it.
			uri = decodeURI(raw_uri);
			if((strcmp(uri, "/streamlist") == 0) || (strcmp(uri, "/") == 0)){
				pthread_mutex_lock(&cPtr->lock);
				if((strcmp(uri, "/") == 0) && cPtr->sc_default){
					// Default uri specified: replace current uri with the specified default value
					free(uri);
					uri = NULL;
					if(strstr(cPtr->sc_default, "/") != cPtr->sc_default)
						// add leading '/' to the default uri
						appendstr(&uri, "/");
					appendstr(&uri, cPtr->sc_default);
					pthread_mutex_unlock(&cPtr->lock);
				}else{
					// request is for listen page: send a listen page that lists the sources being hosted
					if(content = listen_content(sock, cPtr->sourceList)){
						pthread_mutex_unlock(&cPtr->lock);
						sendHttpContent(sock, "text/html", content);
						free(content);
						free(in);
						free(uri);
						close(sock);
						pthread_exit(0);
					}else{
						pthread_mutex_unlock(&cPtr->lock);
						errMsg = "500 Internal Server Error";
						goto fail;
					}
				}
			}
			
			// strip possible file sufix '.' and check for pls sufix
			strtok_r(uri, ".", &value);
			if(value && (strcasecmp(value, "pls") == 0)){
				// uri ends with .pls: listen file request
				if((strlen(uri) > 1) && (content = pls_content(sock, uri+1, cPtr->sourceList))){
					sendHttpContent(sock, "audio/x-scpls", content);
					free(content);
					free(in);
					free(uri);
					close(sock);
					pthread_exit(0);
				}else{
					errMsg = "404 Not Found";
					goto fail;
				}
			}
			// otherwise, this is a shoutcast stream request... verify the requested stream exists
			if((strlen(uri) < 2) || ((rec = getSourceByName(uri+1, cPtr->sourceList)) == NULL) || !rec->sourceStatus || (rec->tc_socket <= -2)){
				// named source does not exist, is down or transcoder is broken... send error message
				errMsg = "404 Not Found";
				goto fail;
			}

			// create listener node						
			if((data = cJSON_CreateObject()) && (ipGrp = cJSON_CreateObject()) && (rep = cJSON_CreateObject())){
				if(agent)
					cJSON_AddStringToObject(data, "Client", agent);
				
				if(rec->sourceName)
					cJSON_AddStringToObject(data, "Stream", rec->sourceName);
				
				if(addr.sin6_family == AF_INET){
					addr4 = (struct sockaddr_in *)&addr;
					if(inet_ntop(AF_INET, &(addr4->sin_addr), ipStr, sizeof(ipStr)))
						cJSON_AddStringToObject(ipGrp, "Addr", ipStr);
					else{
						errMsg = "500a Internal Server Error";
						goto fail;
					}	
					cJSON_AddNumberToObject(ipGrp, "Port", ntohs(addr4->sin_port));
					cJSON_AddFalseToObject(ipGrp, "Relay");
					if(cPtr->sc_identity)
						cJSON_AddStringToObject(ipGrp, "Via", cPtr->sc_identity);
					cJSON_AddItemToObject(data, "IP4", ipGrp);
					ipGrp = NULL;			
					
				}else if(addr.sin6_family == AF_INET6){
					if(inet_ntop(AF_INET6, &(addr.sin6_addr), ipStr, sizeof(ipStr)))
						cJSON_AddStringToObject(ipGrp, "Addr", ipStr);
					else{
						errMsg = "500b Internal Server Error";
						goto fail;
					}						
					cJSON_AddNumberToObject(ipGrp, "Port", htons(addr.sin6_port));
					cJSON_AddFalseToObject(ipGrp, "Relay");
					if(cPtr->sc_identity)
						cJSON_AddStringToObject(ipGrp, "Via", cPtr->sc_identity);
					cJSON_AddItemToObject(data, "IP6", ipGrp);
					
					ipGrp = NULL;
					
				}else{
					errMsg = "500c Internal Server Error";
					goto fail;
				}		
				
				cJSON_AddNumberToObject(rep, "Fix", 0);	// fixed bytes per frame
				cJSON_AddNumberToObject(rep, "Fail", 0);	// % fail frames
				cJSON_AddNumberToObject(rep, "Bad", 0);	// % bad packets
				cJSON_AddNumberToObject(rep, "Dup", 0);	// % Duplicate packets
				cJSON_AddNumberToObject(rep, "Bal", 0);	// % Duplicate packets
				cJSON_AddTrueToObject(rep, "Stat");	// % Status - True = Playing
				cJSON_AddItemToObject(data, "Report", rep);
				rep = NULL;
			
				bzero(&rr, sizeof(struct recvrRecord));
				rr.apparentAddress = addr;
				rr.statedAddress = addr;
				if(cPtr->sc_identity){
					rr.via = malloc(strlen(cPtr->sc_identity) + 1);
					strcpy(rr.via, cPtr->sc_identity);
				}else
					rr.via = NULL;
				rr.meta = data;
				data = NULL;
				rr.relay = 1;
				node = newListenerNode(cPtr, &rr);
				node->relayType = 2;			// shoutcast type, pre-roll new conection
				if(metaFlag)
					node->offset = 0;
				
				// create reply string
				out = NULL;
				appendstr(&out, "ICY 200 OK\r\n");
				appendstr(&out, "icy-notice1:<BR>This is a shoutcast stream<BR>\r\n");
				appendstr(&out, "icy-notice2:");
				appendstr(&out, rec->rsp->clientName);
				appendstr(&out, "<BR>\r\n");
				appendstr(&out, "icy-name:");
				appendstr(&out, rec->sourceName);
				appendstr(&out, "\r\n");						
				
				if(item = cJSON_GetObjectItem(rec->sc_conf, "public")){
					if(item->valueint)
						appendstr(&out, "icy-pub:1\r\n");
					else
						appendstr(&out, "icy-pub:0\r\n");
				}
				if(metaFlag){
					snprintf(buffer, sizeof(buffer), "icy-metaint:%u\r\n", cPtr->sc_metaperiod);
					appendstr(&out, buffer);
				}
				if(item = cJSON_GetObjectItem(rec->sc_conf, "genre")){
					if(item->valuestring && strlen(item->valuestring)){
						appendstr(&out, "icy-genre:");
						appendstr(&out, item->valuestring);
						appendstr(&out, "\r\n");
					}
				}
				if(item = cJSON_GetObjectItem(rec->sc_conf, "url")){
					if(item->valuestring && strlen(item->valuestring)){
						appendstr(&out, "icy-url:");
						appendstr(&out, item->valuestring);
						appendstr(&out, "\r\n");
					}
				}
				if(rec->rsp_conf && (group = cJSON_GetObjectItem(rec->rsp_conf, "reformat")) && (group = cJSON_GetObjectItem(group, "re-encode")) && (group = cJSON_GetObjectItem(group, "Content"))){
					// the stream is being re-coded... send the new content settings
					if(item = cJSON_GetObjectItem(group, "Type")){
						if(item->valuestring && strlen(item->valuestring)){
							// !!!! handle type conversion here

							appendstr(&out, "Content-Type:");
							appendstr(&out, item->valuestring);
							appendstr(&out, "\r\n");
						}else{
							errMsg = "500d Internal Server Error";
							goto fail;
						}
					}
					if(item = cJSON_GetObjectItem(group, "kBitRate")){
						if(item->valueint > 0){
							snprintf(buffer, sizeof(buffer), "icy-br:%u\r\n", item->valueint);
							appendstr(&out, buffer);
						}else{
							errMsg = "500e Internal Server Error";
							goto fail;
						}					
					}
				}else{
					pthread_mutex_lock(&(rec->rsp->metaMutex));
					if(group = cJSON_GetObjectItem(rec->rsp->metaRepeat, "Content")){
						// the stream is NOT being re-coded... send the source content settings
						if(item = cJSON_GetObjectItem(group, "Type")){
							if(item->valuestring && strlen(item->valuestring)){
								// !!!! handle type conversion here
								
								appendstr(&out, "Content-Type:");
								appendstr(&out, item->valuestring);
								appendstr(&out, "\r\n");
							}else{
								pthread_mutex_unlock(&(rec->rsp->metaMutex));
								errMsg = "500f Internal Server Error";
								goto fail;
							}
						}
						if(item = cJSON_GetObjectItem(group, "kBitRate")){
							if(item->valueint > 0){
								snprintf(buffer, sizeof(buffer), "icy-br:%u\r\n", item->valueint);
								appendstr(&out, buffer);
							}else{
								pthread_mutex_unlock(&(rec->rsp->metaMutex));
								errMsg = "500g Internal Server Error";
								goto fail;
							}					
						}
						pthread_mutex_unlock(&(rec->rsp->metaMutex));
					}else{
						pthread_mutex_unlock(&(rec->rsp->metaMutex));
						errMsg = "500h Internal Server Error";
						goto fail;
					}
				}
				appendstr(&out, "\r\n");
				
				if(linkListenerNode(rec->listHead, node, rec, cPtr->log_listeners) == NULL){
					// server is full
					pthread_mutex_unlock(&rec->lock); 
					freeListenerNode(node, FALSE);
					free(out);
					out = NULL;
					appendstr(&out, "ICY 400 server full\r\n\r\n");
					write(sock, out, strlen(out));
					free(out);
					close(sock);
					free(in);	
					free(uri);
					if(cPtr->log_listeners && node->rr.meta && (str = cJSON_PrintUnformatted(node->rr.meta))){
						syslog(LOG_INFO, "Maximum relay listeners exceeded [info=%s]", str);
						free(str);
					}
					pthread_exit(0);
				}
				node->rr.lastHeard = time(NULL);
				
				pthread_mutex_unlock(&rec->lock); 
				write(sock, out, strlen(out));
				free(out);
					
				// set socket to non-blocking before adding it's node to the listener List
				val = fcntl(sock, F_GETFL, 0);
				fcntl(sock, F_SETFL, val | O_NONBLOCK);

				// the next line allows the relay thread to start sending stream data, now that the response has been sent
				node->socket = sock;
											
				free(in);
				if(uri)
					free(uri);
				pthread_exit(0);
			}
		}else{
			errMsg = "505 HTTP Version Not Supported";
			goto fail;
		}
	}
	if(nbytes <= 0){
		errMsg = "408 Request Timeout";
		goto fail;
	}
	
fail:
	// try to send error if socket is still open
	if(rec)
		pthread_mutex_unlock(&rec->lock); 
	if(errMsg == NULL)
		errMsg = "400 Bad Request";
	out = NULL;
	appendstr(&out, "HTTP/1.1 ");
	appendstr(&out, errMsg);
	appendstr(&out, "\r\n\r\n");
	appendstr(&out, "<html><head><title>");
	appendstr(&out, errMsg);
	appendstr(&out, "</title></head><body><center><h1>");
	appendstr(&out, errMsg);
	appendstr(&out, "</h1></center></body></html>\n");
	write(sock, out, strlen(out));
	free(out);
		
	// and close the connection
	close(sock);
	if(node)
		freeListenerNode(node, cPtr->log_listeners);
	if(data)
		cJSON_Delete(data);
	if(ipGrp)
		cJSON_Delete(ipGrp);
	if(rep)
		cJSON_Delete(rep);
	if(in)
		free(in);
	if(uri)
		free(uri);
	
	pthread_exit(0);
}

void *shoutcastListen(void* refCon)
{		
	struct threadPass *tp;
	struct threadPass ctp;
	struct serverContext *cPtr;
	int *sock;
	socklen_t namelen;
	pthread_t sc_session_thread;
	
	tp = (struct threadPass *)refCon;
	cPtr = tp->cPtr;
	sock = tp->sockPtr;
	// signal the parent we are done with the structure pointer that was passed
	tp->sockPtr = NULL;
		
	while(cPtr->run && (*sock > -1)){
		// *sock is closed by main thread before run is false so that accept will unblock and this thread can exit
		ctp.cPtr = cPtr;
		namelen = sizeof(ctp.addr); 
		ctp.sock = accept(*sock, (struct sockaddr *)&ctp.addr, &namelen); /* wait for connection request */
		if(ctp.sock > -1){
			// run a http session thread to negotiate the shoutcast session with the client
			if(pthread_create(&sc_session_thread, NULL, &shoutcastSession, &ctp) == 0){
				while(ctp.sock != -1)
					YIELD();
				pthread_detach(sc_session_thread);
			}else{
				// couldn't create thread to handle request... just close the connection
				write(ctp.sock, "HTTP/1.1 ", 9);
				write(ctp.sock, "500 Internal Server Error", 25);
				write(ctp.sock, "\r\n\r\n", 4);
				close(ctp.sock);
			}
		}
	}
	return NULL;
}

void setDurationString(time_t dur, char *str)
{	
	if(dur < 0){
		strcpy(str, "000000000");
		return;
	}
	sprintf(str, "%.9lu", dur);
}

void syslogSetup(struct serverContext *cPtr, cJSON *settings)
{
	cJSON *item;
	char *ident, *fac, *level;
	int facID, levelID;

	closelog();

	ident = "rspServer";
	fac = "";
	facID = LOG_USER;
	level = "";
	levelID = LOG_ERR;
	if(settings && (item = cJSON_GetObjectItem(settings, "identity"))){
		if(item->valuestring && strlen(item->valuestring))
			ident = item->valuestring;
	}
	if(settings && (item = cJSON_GetObjectItem(settings, "facility"))){
		if(item->valuestring && strlen(item->valuestring))
			fac = item->valuestring;
	}
	if(settings && (item = cJSON_GetObjectItem(settings, "level"))){
		if(item->valuestring && strlen(item->valuestring))
			level = item->valuestring;
	}
		  
	if(strcmp(fac, "LOG_KERN") == 0) facID = LOG_KERN;
	else if(strcmp(fac, "LOG_USER") == 0) facID = LOG_USER;
	else if(strcmp(fac, "LOG_MAIL") == 0) facID = LOG_MAIL;
	else if(strcmp(fac, "LOG_DAEMON") == 0) facID = LOG_DAEMON;
	else if(strcmp(fac, "LOG_AUTH") == 0) facID = LOG_AUTH;
	else if(strcmp(fac, "LOG_SYSLOG") == 0) facID = LOG_SYSLOG;
	else if(strcmp(fac, "LOG_LPR") == 0) facID = LOG_LPR;
	else if(strcmp(fac, "LOG_NEWS") == 0) facID = LOG_NEWS;
	else if(strcmp(fac, "LOG_UUCP") == 0) facID = LOG_UUCP;
	else if(strcmp(fac, "LOG_CRON") == 0) facID = LOG_CRON;
	else if(strcmp(fac, "LOG_FTP") == 0) facID = LOG_FTP;
#ifdef __APPLE__	
	else if(strcmp(fac, "LOG_NETINFO") == 0) facID = LOG_NETINFO;
	else if(strcmp(fac, "LOG_REMOTEAUTH") == 0) facID = LOG_REMOTEAUTH;
	else if(strcmp(fac, "LOG_INSTALL") == 0) facID = LOG_INSTALL;
	else if(strcmp(fac, "LOG_RAS") == 0) facID = LOG_RAS;
#endif	
	else if(strcmp(fac, "LOG_LOCAL0") == 0) facID = LOG_LOCAL0;
	else if(strcmp(fac, "LOG_LOCAL1") == 0) facID = LOG_LOCAL1;
	else if(strcmp(fac, "LOG_LOCAL2") == 0) facID = LOG_LOCAL2;
	else if(strcmp(fac, "LOG_LOCAL3") == 0) facID = LOG_LOCAL3;
	else if(strcmp(fac, "LOG_LOCAL4") == 0) facID = LOG_LOCAL4;
	else if(strcmp(fac, "LOG_LOCAL5") == 0) facID = LOG_LOCAL5;
	else if(strcmp(fac, "LOG_LOCAL6") == 0) facID = LOG_LOCAL6;
	else if(strcmp(fac, "LOG_LOCAL7") == 0) facID = LOG_LOCAL7;
	else{
		fprintf(stderr, "Bad or no syslog facility specified.  Using the default value of LOG_USER.\n");
	}
	openlog(ident, LOG_NDELAY | LOG_CONS, facID);
	   		   
	if(settings && (item = cJSON_GetObjectItem(settings, "log_listeners"))){
		if(item->valueint)
			cPtr->log_listeners = TRUE;
		else
			cPtr->log_listeners = FALSE;
	}else{
		cPtr->log_listeners = FALSE;
		fprintf(stderr, "No syslog listener logging flag specified.  Using the default value of FALSE (listener logging off)\n");
		syslog(LOG_WARNING, "No syslog listener logging flag specified.  Using the default value of FALSE (listener logging off)");
	}
	
	if(strcmp(level, "LOG_EMERG") == 0) levelID = LOG_EMERG;
	else if(strcmp(level, "LOG_ALERT") == 0) levelID = LOG_ALERT;
	else if(strcmp(level, "LOG_CRIT") == 0) levelID = LOG_CRIT;
	else if(strcmp(level, "LOG_ERR") == 0) levelID = LOG_ERR;   
	else if(strcmp(level, "LOG_WARNING") == 0) levelID = LOG_WARNING;
	else if(strcmp(level, "LOG_NOTICE") == 0) levelID = LOG_NOTICE;
	else if(strcmp(level, "LOG_INFO") == 0) levelID = LOG_INFO;
	else if(strcmp(level, "LOG_DEBUG") == 0) levelID = LOG_DEBUG;
	else{
		fprintf(stderr, "Bad or no syslog level specified.  Using the default value of LOG_ERR.\n");
		syslog(LOG_WARNING, "Bad or no syslog level specified.  Using the default value of LOG_ERR.");
	}
	if(cPtr->log_listeners && (levelID < LOG_INFO)){
		levelID = LOG_INFO;
		fprintf(stderr, "Listener logging is enabled.  Overriding syslog level to LOG_INFO.\n");
		syslog(LOG_WARNING, "Listener logging is enabled.  Overriding syslog level to LOG_INFO.");
	}
	setlogmask(LOG_UPTO(levelID));
}

unsigned char configureServer(FILE * fd, struct serverContext *cPtr)
{
	// returns 0 if configuration suceeded (context settings are now representetive of the configuration)
	//		Any non-fatal errors which may have been encountered durring configuration, such as an
	//		invalid preset listener, or a bad source file, are noted via error messages sent to stderr.
	//		This function will attempt to leave existing listeners uninterupted if possible.
	//
	// returns 1 if configuration failed (previous context settings, if any, are left unmodified)
	//		Existing listeners are uninterupted and the server will continue to operate under the previous 
	//		configuration, if any.
	
	// cPtr lock should be locked prior to this is called when trying to update the current configuration while threads are already running
	
	const char * const check[] = { "Port", "Bind", NULL };
	cJSON *item, *old, *group, *subgrp, *sources, *relay, *reports, *root;
	unsigned short s_count;
	int ns_socket, svr_socket4, svr_socket6, tmp_socket;
	char *old_ns_name;
	unsigned char flag;
	unsigned char shutdown_soures;
	struct threadPass tp;
	
	ns_socket = -1;
	svr_socket4 = -1;
	svr_socket6 = -1;
	old_ns_name = NULL;
	shutdown_soures = FALSE;
	
	s_count = readConfigFile(fd, &root, &sources, &relay, &reports);
	if(root == NULL){
		fprintf(stderr, "Configuration failed: Configuration file contains a jSON format error.\n");
		goto fail;
	}
	
	// set up syslog settings
	if(group = cJSON_GetObjectItem(root, "syslog"))
//	if(!cPtr->root_conf || (compareItems(group, cJSON_GetObjectItem(cPtr->root_conf, "syslog"), NULL) == FALSE))
		syslogSetup(cPtr, group);
	
	// set up status/relay server UDP sockets
	flag = FALSE;
	if(!cPtr->root_conf || (compareItems(cJSON_GetObjectItem(root, "IP4"), cJSON_GetObjectItem(cPtr->root_conf, "IP4"), check) == FALSE)){
		if((svr_socket4 = serverNetworkSetup(root, FALSE, SOCK_DGRAM)) < 0){
			fprintf(stderr, "No valid IPv4 server UDP network socket configuration. Previous socket, if any will be closed.\n");
			syslog(LOG_WARNING, "No valid IPv4 server UDP network socket configuration. Previous socket, if any will be closed.");
			cJSON_DeleteItemFromObject(root, "IP4");
		}
	}else{
		if(cPtr->svr_socket4 > -1)
			svr_socket4 = cPtr->svr_socket4;	// keeping existing socket
	}
	// set optional socket DiffServ settings
	if(svr_socket4 > -1){
		if(group = cJSON_GetObjectItem(root, "IP4")){
			if(item = cJSON_GetObjectItem(group, "diffServHex")){
				if(item->valuestring && strlen(item->valuestring)){
					int dsval;
					dsval = strtoul(item->valuestring, NULL, 16);
					dsval = dsval & 0xFB;  // upper six bits only are valid
					if(setsockopt(svr_socket4, IPPROTO_IP, IP_TOS, &dsval, sizeof(dsval)) < 0){
						fprintf(stderr, "Failed to set IPv4 server UDP socketr DiffServ bits.\n");
						syslog(LOG_WARNING, "Failed to set IPv4 server UDP socketr DiffServ bits.");
					}else{
						fprintf(stderr, "IPv4 server UDP socketr DiffServ bits have been set.\n");
						syslog(LOG_WARNING, "IPv4 server UDP socketr DiffServ bits have been set.");
						
					}
				}
			}
		}
	}
	
	if(!cPtr->root_conf || (compareItems(cJSON_GetObjectItem(root, "IP6"), cJSON_GetObjectItem(cPtr->root_conf, "IP6"), check) == FALSE)){
		if((svr_socket6 = serverNetworkSetup(root, TRUE, SOCK_DGRAM)) < 0){
			fprintf(stderr, "No valid IPv6 server UDP network socket configuration. Previous socket, if any will be closed.\n");
			syslog(LOG_WARNING, "No valid IPv6 server UDP network socket configuration. Previous socket, if any will be closed.");
			cJSON_DeleteItemFromObject(root, "IP6");
		}
	}else{
		if(cPtr->svr_socket6 > -1)
			svr_socket6 = cPtr->svr_socket6;	// keeping existing socket
	}
	// set optional socket DiffServ settings
#ifdef IPV6_TCLASS
	if(svr_socket6 > -1){
		if(group = cJSON_GetObjectItem(root, "IP6")){
			if(item = cJSON_GetObjectItem(group, "diffServHex")){
				if(item->valuestring && strlen(item->valuestring)){
					int dsval;
					dsval = strtoul(item->valuestring, NULL, 16);
					dsval = dsval & 0xFB;  // upper six bits only are valid
					if(setsockopt(svr_socket6, IPPROTO_IPV6, IPV6_TCLASS, &dsval, sizeof(dsval)) < 0){
						fprintf(stderr, "Failed to set IPv6 server UDP socketr DiffServ bits.\n");
						syslog(LOG_WARNING, "Failed to set IPv6 server UDP socketr DiffServ bits.");
					}else{
						fprintf(stderr, "IPv6 server UDP socketr DiffServ bits have been set.\n");
						syslog(LOG_WARNING, "IPv6 server UDP socketr DiffServ bits have been set.");
						
					}
				}
			}
		}
	}
#endif
	
	// check for at least one valid new or unchanged socket
	if((svr_socket4 < 0) && (svr_socket6 < 0)){
		fprintf(stderr, "Configuration failed: No valid server UDP network socket.\n");
		syslog(LOG_ERR, "Configuration failed: No valid server UDP network socket.");
		goto fail;
	}
	// set up named socket for server control
	if(((item = cJSON_GetObjectItem(root, "controlSocket")) == NULL) || (item->valuestring == NULL) || (strlen(item->valuestring) == 0)){
		fprintf(stderr, "Configuration failed: Missing 'controlSocket' setting in configuration.\n");
		syslog(LOG_ERR, "Configuration failed: Missing 'controlSocket' setting in configuration.");
		goto fail;
	}
	if(!cPtr->root_conf)
		old = NULL;
	else
		old = cJSON_GetObjectItem(cPtr->root_conf, "controlSocket");
	if(old && old->valuestring && strlen(old->valuestring))
		old_ns_name = old->valuestring;
	if(compareItems(item, old, NULL) == FALSE){
		// create named socket for control access
		struct sockaddr_un address;
				
		if((ns_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
			fprintf(stderr, "Configuration failed: Failed to create server control socket.\n");
			syslog(LOG_ERR, "Configuration failed: Failed to create server control socket.");
			goto fail;
		}
		address.sun_family = AF_UNIX;
		strncpy(address.sun_path, item->valuestring, sizeof(address.sun_path));
		
		unlink(item->valuestring);
		
		if(bind(ns_socket, (struct sockaddr *)&address, offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path)) == -1){
			fprintf(stderr, "Configuration failed: Couln't name control socket; see 'controlSocket' setting in configuration.\n");
			syslog(LOG_ERR, "Configuration failed: Couln't name control socket; see 'controlSocket' setting in configuration.");
			goto fail;
		}
		
		// set socket permission to read/write owner and group
		chmod(item->valuestring, 0660);

		if(listen(ns_socket, 5) != 0){
			fprintf(stderr, "Configuration failed: Couldn't to set control socket to listen for connections.\n");
			syslog(LOG_ERR, "Configuration failed: Couldn't to set control socket to listen for connections.");
			goto fail;
		}
	}else{
		if(cPtr->ns_socket < 0){
			fprintf(stderr, "Configuration failed: No existing control socket; See 'controlSocket' setting in configuration.\n");
			syslog(LOG_ERR, "Configuration failed: No existing control socket; See 'controlSocket' setting in configuration.");
			goto fail;
		}else
			ns_socket = cPtr->ns_socket;

	}

	// ********** non-fatal server properties **********

	if(old_ns_name && (ns_socket != cPtr->ns_socket))
		unlink(old_ns_name);
	if((cPtr->ns_socket > -1) && (ns_socket != cPtr->ns_socket))
		close(cPtr->ns_socket);
	cPtr->ns_socket = ns_socket;
	
	// we need to create an rsp session, even if we are not relaying a rsp stream, to parse listener reports.
	// it does not need to be initialized unless we are relaying, which we will do later if needed.
	if(cPtr->rep_rsp == NULL)
		cPtr->rep_rsp = rspSessionNew(clientID);
	// replace or set server sockets
	if(svr_socket4 != cPtr->svr_socket4){
		if(cPtr->svr_socket4 > -1)
			close(cPtr->svr_socket4);
		cPtr->svr_socket4 = svr_socket4;
		if(svr_socket4 > -1){
			fprintf(stderr, "IPv4 server UDP network socket has new configuration.\n");
			syslog(LOG_NOTICE, "IPv4 server UDP network socket has new configuration.");
		}else{
			fprintf(stderr, "IPv4 server UDP network socket is no longer used.\n");
			syslog(LOG_NOTICE, "IPv4 server UDP network socket is no longer used.");
		}
	}
	if(svr_socket6 != cPtr->svr_socket6){
		if(cPtr->svr_socket6 > -1)
			close(cPtr->svr_socket6);
		cPtr->svr_socket6 = svr_socket6;
		if(svr_socket6 > -1){
			fprintf(stderr, "IPv6 server UDP network socket has new configuration.\n");
			syslog(LOG_NOTICE, "IPv6 server UDP network socket has new configuration.");
		}else{
			fprintf(stderr, "IPv6 server UDP network socket is no longer used.\n");
			syslog(LOG_NOTICE, "IPv6 server UDP network socket is no longer used.");
		}
	}
	if(cPtr->listHead == NULL)
		cPtr->listHead = newListenerNode(cPtr, NULL);
	
	if(relay && s_count){
		group = cJSON_GetObjectItem(relay, "shoutcast");
		if(!cPtr->root_conf)
			old = NULL;
		else{
			if(old = cJSON_GetObjectItem(cPtr->root_conf, "relay"))
				old = cJSON_GetObjectItem(old, "shoutcast");
		}
		if(group && (compareItems(group, old, NULL) == FALSE)){
			if(!old || (compareItems(cJSON_GetObjectItem(group, "IP4"), cJSON_GetObjectItem(old, "IP4"), check) == FALSE)){
				// create IPv4 listening sockets
				tmp_socket = -1;
				tmp_socket = serverNetworkSetup(group, FALSE, SOCK_STREAM);
				if(listen(tmp_socket, 1) != 0){
					close(tmp_socket);
					tmp_socket = -1;
					fprintf(stderr, "Failed to create IPv4 Shoutcast listening socket.\n");
					syslog(LOG_NOTICE, "Failed to create IPv4 Shoutcast listening socket.");
					cJSON_DeleteItemFromObject(group, "IP4");
				}
				if((cPtr->sc_socket4 == -1) && (tmp_socket > -1)){
					// start sc listen thread
					cPtr->sc_socket4 = tmp_socket;
					tp.cPtr = cPtr;
					tp.sockPtr = &cPtr->sc_socket4;
//					setsockopt(cPtr->sc_socket4, SOL_SOCKET, SO_NOSIGPIPE, NULL, 0);	
					// run a shoutcast listener thread for IPv4
					if(pthread_create(&cPtr->scListen4_thread, NULL, &shoutcastListen, &tp) == 0){
						while(tp.sockPtr != NULL)
							YIELD();
					}else{
						fprintf(stderr, "Failed to create IPv4 Shoutcast listening thread.\n");
						syslog(LOG_NOTICE, "Failed to create IPv4 Shoutcast listening socket.");
						cJSON_DeleteItemFromObject(group, "IP4");
					}
				}else{
					if(cPtr->sc_socket4 > -1)
						close(cPtr->sc_socket4);
					// just update the socket... existing thread will use new socket or stop running if existing socket was closed
					cPtr->sc_socket4 = tmp_socket;
				}
			}
			if(!old || (compareItems(cJSON_GetObjectItem(group, "IP6"), cJSON_GetObjectItem(old, "IP6"), check) == FALSE)){
				// create IPv6 listening sockets
				tmp_socket = -1;
				tmp_socket = serverNetworkSetup(group, TRUE, SOCK_STREAM);
				if(listen(tmp_socket, 1) != 0){
					close(tmp_socket);
					tmp_socket = -1;
					fprintf(stderr, "Failed to create IPv6 Shoutcast listening socket.\n");
					syslog(LOG_NOTICE, "Failed to create IPv6 Shoutcast listening socket.");
					cJSON_DeleteItemFromObject(group, "IP6");
				}
				if((cPtr->sc_socket6 == -1) && (tmp_socket > -1)){
					// start sc listen thread
					cPtr->sc_socket6 = tmp_socket;
					tp.cPtr = cPtr;
					tp.sockPtr = &cPtr->sc_socket6;
//					setsockopt(cPtr->sc_socket6, SOL_SOCKET, SO_NOSIGPIPE, NULL, 0);	
					// run a shoutcast listener thread for IPv6
					if(pthread_create(&cPtr->scListen6_thread, NULL, &shoutcastListen, &tp) == 0){
						while(tp.sockPtr != NULL)
							YIELD();
					}else{
						fprintf(stderr, "Failed to create IPv6 Shoutcast listening thread.\n");
						syslog(LOG_NOTICE, "Failed to create IPv6 Shoutcast listening socket.");
						cJSON_DeleteItemFromObject(group, "IP6");
					}
				}else{
					if(cPtr->sc_socket6 > -1)
						close(cPtr->sc_socket6);
					// just update the socket... existing thread will use new socket or stop running if existing socket was closed
					cPtr->sc_socket6 = tmp_socket;
				}
			}
			
			item = cJSON_GetObjectItem(group, "viaIdentity");
			if(!old || (compareItems(item, cJSON_GetObjectItem(old, "viaIdentity"), NULL) == FALSE)){
				if(cPtr->sc_identity)
					free(cPtr->sc_identity);
				cPtr->sc_identity = NULL;
				if(item && item->valuestring && strlen(item->valuestring)){
					cPtr->sc_identity = (char *)malloc(strlen(item->valuestring) + 1);
					strcpy(cPtr->sc_identity, item->valuestring);
				}
			}
			
			item = cJSON_GetObjectItem(group, "defaultRequest");
			if(!old || (compareItems(item, cJSON_GetObjectItem(old, "defaultRequest"), NULL) == FALSE)){
				if(cPtr->sc_default)
					free(cPtr->sc_default);
				if(item && item->valuestring && strlen(item->valuestring)){
					cPtr->sc_default = (char *)malloc(strlen(item->valuestring) + 1);
					strcpy(cPtr->sc_default, item->valuestring);
				}
			}
			
			unsigned int old_meta_period = cPtr->sc_metaperiod;
			if(item = cJSON_GetObjectItem(group, "metaPeriod"))
				cPtr->sc_metaperiod = item->valueint;
			else
				cPtr->sc_metaperiod = 8192;
			if(old_meta_period != cPtr->sc_metaperiod)
				// we will need to restart all the sources when we change the shoutcast meta period
				// since existing shoutcast connections are expecting meta data to be interleave using 
				// the old period and we can't just change it on them with out disconnecting them first.
				shutdown_soures = TRUE;
			if(item = cJSON_GetObjectItem(group, "sockTimeout"))
				cPtr->sc_sock_timeout = item->valueint;
			else
				cPtr->sc_sock_timeout = 30;
			if(item = cJSON_GetObjectItem(group, "reportPeriod"))
				cPtr->sc_reportperiod = item->valueint;
			else
				cPtr->sc_reportperiod = 0; // do not report shoutcast listeners to the report forwarding address
		}
		group = cJSON_GetObjectItem(relay, "rsp");
		if(cPtr->root_conf){
			old = cJSON_GetObjectItem(cPtr->root_conf, "relay");
		}else
			old = NULL;
		
		if(compareItems(group, old, NULL) == FALSE){
			if(cPtr->relay_identity)
				free(cPtr->relay_identity);
			cPtr->relay_identity = NULL;			
			if(group && (item = cJSON_GetObjectItem(group, "viaIdentity"))){
				if(item->valuestring && strlen(item->valuestring)){
					cPtr->relay_identity = (char *)malloc(strlen(item->valuestring) + 1);
					strcpy(cPtr->relay_identity, item->valuestring);
				}
			}
		}
		// get old sources array
		if(old)
			group = cJSON_GetObjectItem(old, "sources");
		else
			group = NULL;
		
		// compare old with new to see if we need to make changes. Even if we don't make changes, 
		// we need to re-reference each source's jSON object to the new settings jSON object so we 
		// can release the old root_config jSON object and replace it with the new one.
		cJSON *child;
		struct sourceRecord *rec, *newrec;
		int i = 1;
		
		// and check for new and changed sources
		if(sources){
			child = sources->child;
			while(child){
				if(item = cJSON_GetObjectItem(child, "Name")){
					if(item->valuestring && strlen(item->valuestring)){
						if(rec = getSourceByName(item->valuestring, cPtr->sourceList)){
							// try reconfiguiting existing record
							if(!shutdown_soures && initSourceNode(rec, cPtr, child)){
								// existing record was reconfigured
								pthread_mutex_unlock(&rec->lock); 
							}else{
								// could not reconfigured existing record  
								pthread_mutex_unlock(&rec->lock); 
								// unlink and free existing record, then try again.
								unlinkSourceNode(rec, cPtr->sourceList);
								freeSourceNode(rec, cPtr->log_listeners);
								rec = NULL;
							}
						}
						if(rec == NULL){
							// either no existing record, or the existing record couldn't be updated... try creating a new one
							if(newrec = initSourceNode(NULL, cPtr, child))
								// link the new record into the source list
								linkSourceNode(newrec, cPtr->sourceList);
							else{
								fprintf(stderr, "Source '%s' could not be configured with the supplied settings. Continuing...\n", item->valuestring);
								syslog(LOG_NOTICE, "Source '%s' could not be configured with the supplied settings. Continuing...", item->valuestring);
							}
						}
					}else{
						fprintf(stderr, "Source number %d was skipped because it's name is empty. Continuing...\n", i);
						syslog(LOG_NOTICE, "Source number %d was skipped because it's name is empty. Continuing...", i);
					}
				}else{
					fprintf(stderr, "Source number %d was skipped because it has no name. Continuing...\n", i);
					syslog(LOG_NOTICE, "Source number %d was skipped because it has no name. Continuing...", i);
				}
				child = child->next;
				i++;
			}
		}
		if(group){
			// remove old sources
			child = group->child;
			while(child){
				if(findMatchingItemInArray(child, sources, "Name") == -1){
					// item not in new source list... remove it.
					if(item = cJSON_GetObjectItem(child, "Name")){
						if(item->valuestring && strlen(item->valuestring)){
							if(rec = getSourceByName(item->valuestring, cPtr->sourceList)){
								pthread_mutex_unlock(&rec->lock);
								unlinkSourceNode(rec, cPtr->sourceList);
								freeSourceNode(rec, cPtr->log_listeners);
							}
						}
					}
				}
				child = child->next;
			}
		}
	}
	
	// remove and close old named socket, and such.  Might as well commit configurations too since we won't fail at this point.
	// release old config cJSON object if any
	if(cPtr->root_conf)
		cJSON_Delete(cPtr->root_conf);
	// and set config cJSON object
	cPtr->root_conf = root;	
	
	cPtr->relay_timeout = 0;
	if(reports){
		if(item = cJSON_GetObjectItem(reports, "timeout"))
			cPtr->relay_timeout = (unsigned int)item->valueint;
		
		bzero(&cPtr->forwardAddress, sizeof(struct sockaddr_in6));
		fprintf(stderr, "Report forwarding disabled. Continuing...\n");
		syslog(LOG_NOTICE, "Report forwarding disabled. Continuing...");
		if(group = cJSON_GetObjectItem(reports, "forwarding")){
			char *host;
			unsigned int portno;
			
			if(subgrp = cJSON_GetObjectItem(group, "IP6"))
				flag = TRUE;
			else if(subgrp = cJSON_GetObjectItem(group, "IP4"))
				flag = FALSE;
			if(subgrp){
				if(item = cJSON_GetObjectItem(subgrp, "Host")){
					if(item->valuestring && strlen(item->valuestring)){
						host = item->valuestring;
						if(item = cJSON_GetObjectItem(subgrp, "Port")){
							if(portno = item->valueint){
								// try to set the address record for report forwarding
								if(!setSockAddr(&cPtr->forwardAddress, flag, portno, host)){
									fprintf(stderr, "Failed to setup report forwarding. Continuing...\n");
									syslog(LOG_NOTICE, "Failed to setup report forwarding. Continuing...");
									bzero(&cPtr->forwardAddress, sizeof(struct sockaddr_in6));
								}else{
									fprintf(stderr, "Report forwarding set to %s port %u. Continuing...\n", host, portno);
									syslog(LOG_NOTICE, "Report forwarding set to %s port %u. Continuing...", host, portno);
								}
							}
						}
					}
				}
			}
		}
	}
		
	// start the receiver report listener thread
	tp.cPtr = cPtr;
	if((!cPtr->reportV4_thread && (svr_socket4 > -1)) || ((cPtr->svr_socket4 != svr_socket4) && (cPtr->svr_socket4 > -1))){
		if(cPtr->reportV4_thread == NULL){
			// run a report listener thread for IPv4
			tp.sockPtr = &cPtr->svr_socket4;
			if(pthread_create(&cPtr->reportV4_thread, NULL, &reportTask, &tp) == 0){
				while(tp.sockPtr != NULL)
					YIELD();
			}else{
				fprintf(stderr, "Failed to create IPv4 report listening thread. Continuing...\n");
				syslog(LOG_NOTICE, "Failed to create IPv4 report listening thread. Continuing...");
				return TRUE;
			}
		}
	}else{
		if(svr_socket4 < 0)
			// setting the socket to -1 should have caused the corrisponding report thread to quit
			cPtr->reportV4_thread = NULL;
	}
	
	if((!cPtr->reportV6_thread && (svr_socket6 > -1)) || ((cPtr->svr_socket6 != svr_socket6) && (cPtr->svr_socket6 > -1))){
		if(cPtr->reportV6_thread == NULL){
			// run a report listener thread for IPv6
			tp.sockPtr = &cPtr->svr_socket6;
			if(pthread_create(&cPtr->reportV6_thread, NULL, &reportTask, &tp) == 0){
				while(tp.sockPtr != NULL)
					YIELD();
			}else{
				fprintf(stderr, "Failed to create IPv6 report listening thread. Continuing...\n");
				syslog(LOG_NOTICE, "Failed to create IPv6 report listening thread. Continuing...");
				return TRUE;
			}
		}else{
			if(svr_socket6 < 0)
				// setting the socket to -1 should have caused the corrisponding report thread to quit
				cPtr->reportV6_thread = NULL;
		}
	}
	
	// if a named socket group is specified, set the socket group-id to the named group
	if(group = cJSON_GetObjectItem(root, "controlSocketGroup")){
		if(group->valuestring && strlen(group->valuestring)){
			struct group grp, *tempGrpPtr;
			struct group *grpptr;
			int  grplinelen, rcode;
			char *grpbuffer;
			
			grpptr = &grp;
			grplinelen = 1024;
			grpbuffer = (char *)malloc(grplinelen);
			while((rcode = getgrnam_r(group->valuestring, grpptr, grpbuffer, grplinelen, &tempGrpPtr)) == ERANGE){
				// need a bigger buffer...
				grplinelen = grplinelen + 1024;
				if((grpbuffer = realloc(grpbuffer, grplinelen)) == NULL)
					break;
			}
			if((rcode == 0) && tempGrpPtr && (item = cJSON_GetObjectItem(root, "controlSocket")) && item->valuestring)
				rcode = chown(item->valuestring, getuid(), grp.gr_gid);
			if(rcode){
				fprintf(stderr, "Failed to set control socket permission group to %s. Continuing...\n", item->valuestring);
				syslog(LOG_NOTICE, "Failed to set control socket permission group to %s. Continuing...", item->valuestring);
				cJSON_DeleteItemFromObject(root, "controlSocketGroup");
			}
			free(grpbuffer);				
		}
	}
	return FALSE;
	
fail:
	// close any new sockets we were able to set up
	if(ns_socket > -1)
		close(ns_socket);
	if(svr_socket4 > -1)
		close(svr_socket4);
	if(svr_socket6 > -1)
		close(svr_socket6);
	
	return TRUE;
}

void processCommand(int sd, struct serverContext *cPtr, const char *command)
{
	char buf[256];
	int size;

	if(strcmp(command, "shutdown") == 0){
		cPtr->run = FALSE;
		shutdown(cPtr->ns_socket, SHUT_RDWR);
		close(cPtr->ns_socket);
		cPtr->ns_socket = -1;
		return;
	}
	if(strcmp(command, "reload") == 0){
		FILE *confFile;
		const char *path;
		
		path = command + strlen(command) + 1;
		if(*path == 0){
			size = snprintf(buf, sizeof buf, "relaod failed: No configuration file path specified.\n");
			write(sd, buf, size);
			return;
		}
		// Open the specified configuration file
		confFile = fopen(path, "r");		
		if(confFile == NULL){
			size = snprintf(buf, sizeof buf, "relaod failed: Could not open the specified configuration file.\n");
			write(sd, buf, size);
			return;
		}
		pthread_mutex_lock(&cPtr->lock);
		if(configureServer(confFile, cPtr)){
			pthread_mutex_unlock(&cPtr->lock);
			size = snprintf(buf, sizeof buf, "relaod failed: There was a problem with the specified configuration file.\n");
			write(sd, buf, size);
			fclose(confFile);
			return;
		}
		pthread_mutex_unlock(&cPtr->lock);
		fclose(confFile);
		// save the file path used to configure the server
		if(cPtr->conf_file)
			free(cPtr->conf_file);
		cPtr->conf_file = malloc(strlen(path)+1);
		strcpy(cPtr->conf_file, path);

		size = snprintf(buf, sizeof buf, "reload suceeded.\n");
		write(sd, buf, size);
		return;
	}
	if(strcmp(command, "status") == 0){
		// this returns the over-all server stats and the status of each fo the sources being relayed
		
		struct sourceRecord *prev_s, *cur_s;
		unsigned char sc;
		char *pub, *stat, *rsp;
		cJSON *item;
		
		sc = FALSE;
		pthread_mutex_lock(&cPtr->lock);
		if((cPtr->sc_socket6 > -1) || (cPtr->sc_socket4 > -1))
			sc = TRUE;

		size = snprintf(buf, sizeof buf, "%s, Configured from file: %s\n", clientID, cPtr->conf_file);
		write(sd, buf, size);
		if(cPtr->relay_identity){
			size = snprintf(buf, sizeof buf, "RSP Relay Identity: %s\n", cPtr->relay_identity);
			write(sd, buf, size);
		}else{
			size = snprintf(buf, sizeof buf, "RSP Relay Identity: NONE\n");
			write(sd, buf, size);
		}
		if(cPtr->sc_identity){
			size = snprintf(buf, sizeof buf, "Shoutcast Relay Identity: %s\n", cPtr->sc_identity);
			write(sd, buf, size);
		}else{
			size = snprintf(buf, sizeof buf, "Shoutcast Relay Identity: NONE\n");
			write(sd, buf, size);
		}
		if((cPtr->sc_socket4 > 0) || (cPtr->sc_socket6 > 0)){
			size = snprintf(buf, sizeof buf, "Shoutcast Relay Emulation: YES\n");
			write(sd, buf, size);
		}else{
			size = snprintf(buf, sizeof buf, "Shoutcast Relay Emulation: NO\n");
			write(sd, buf, size);
		}
		pthread_mutex_unlock(&cPtr->lock);
		// travers source list
		prev_s = cPtr->sourceList;
		pthread_mutex_lock(&prev_s->lock); 
		if(prev_s->next == NULL){
			size = snprintf(buf, sizeof buf, "Relaying Sources: NONE\n");
			write(sd, buf, size);
		}else{
			size = snprintf(buf, sizeof buf, "Relaying Sources:\n");
			write(sd, buf, size);
			size = snprintf(buf, sizeof buf, "Name\tFEC,IL,Size,C/R\tStatus\tShoutcast\tListeners\tLimit\tPeak\tBalance\tPace(mS)\tCluCnt\n");
			write(sd, buf, size);
			while(cur_s = prev_s->next){ 
				pthread_mutex_lock(&cur_s->lock); 
				pthread_mutex_unlock(&prev_s->lock);
				if(cur_s->sourceName){
					char rsp_str[16];
					if(cur_s->rsp){
						if(cur_s->rsp->interleaver == NULL){
							rsp = "WAITING";
						}else{
							char c, r;
							if(cur_s->rsp->flags & RSP_FLAG_CRC)
								c = 'C';
							else
								c = '-';
							if(cur_s->rsp->flags & RSP_FLAG_RS)
								r = 'R';
							else
								r = '-';
							snprintf(rsp_str, sizeof rsp_str, "%u,%u,%u,%c%c", cur_s->rsp->FECroots, 
													cur_s->rsp->interleaving, cur_s->rsp->colSize, c, r);
							rsp = rsp_str;
						}
					}else{
						rsp = "UNKNOWN";
					}
					
					char stat_str[48];
					float fec_stat;
					if(cur_s->rsp->FECroots)
						fec_stat = cur_s->rsp->FECStat / cur_s->rsp->FECroots;
					else 
						fec_stat = 0.0;
					if(cur_s->tc_socket == -2){
						if(cur_s->rsp){
							snprintf(stat_str, sizeof stat_str, "BROKEN (%.0f/%.0f/%.0f/%.0f)", 100. * fec_stat, 
									 cur_s->rsp->ErrStat * 100., cur_s->rsp->BadStat * 100., cur_s->rsp->DupStat * 100.);
							stat = stat_str;
						}else{
							stat = "BROKEN";
						}
					}else if(cur_s->sourceStatus){
						if(cur_s->rsp){
							snprintf(stat_str, sizeof stat_str, "UP (%.0f/%.0f/%.0f/%.0f)", 100. * fec_stat, 
									 cur_s->rsp->ErrStat * 100., cur_s->rsp->BadStat * 100., cur_s->rsp->DupStat * 100.);
							stat = stat_str;
						}else{
							stat = "UP";
						}
					}else{
						if(cur_s->rsp){
							snprintf(stat_str, sizeof stat_str, "DOWN (%.0f/%.0f/%.0f/%.0f)", 100. * fec_stat, 
									 cur_s->rsp->ErrStat * 100., cur_s->rsp->BadStat * 100., cur_s->rsp->DupStat * 100.);
							stat = stat_str;
						}else{
							stat = "DOWN";
						}
					}

					if(sc){
						pub = "NO";
						if(item = cJSON_GetObjectItem(cur_s->sc_conf, "public")){
							if(item->valueint)
								pub = "YES";
						}
					}else
						pub = "NONE";
					size = snprintf(buf, sizeof buf, "%s\t%s\t%s\t%s\t%.1f/%u\t%u\t%u\t%.2f\t%.2f\t%u\n", cur_s->sourceName, 
									rsp, stat, pub, cur_s->relay_count, cur_s->listener_count, cur_s->relay_limit, 
									cur_s->listener_peak, rspSessionGetBalance(cur_s->rsp), 
									cur_s->rsp->wrRate * 1000., cur_s->rsp->relay_cluster);
					write(sd, buf, size);
				}
				prev_s = cur_s; 
			} 
		}
		pthread_mutex_unlock(&prev_s->lock);
		return;
	}
	if(strcmp(command, "list") == 0){
		const char *source;
		struct listenerNode	*prev, *current; 
		struct sourceRecord *sPtr;
		char *result;
		char *mgrp;
		char *client;
		char *stream;
		char clstat[32];
		char joined[32];
		char heard[32];
		char adrStr[49];
		struct sockaddr_in *addr;
		cJSON *item;
		unsigned short limit, rcount;
		unsigned int count, relay, port;
		
		limit = 0;
		rcount = 0;
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			pthread_mutex_lock(&cPtr->lock);
			prev = cPtr->listHead;
		}else{
			if(sPtr = getSourceByName(source, cPtr->sourceList)){
				prev = sPtr->listHead;
				rcount = sPtr->relay_count;
				limit = sPtr->relay_limit;
			}else{
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				return;
			}
		}
		result = NULL;
		count = 0;
		relay = 0;
		pthread_mutex_lock(&prev->lock); 
		while(current = prev->link){ 
			pthread_mutex_lock(&current->lock); 
			pthread_mutex_unlock(&prev->lock);
			setDurationString(difftime(time(NULL), current->joined), joined);
			if(current->rr.lastHeard == 0)
				strcpy(heard, "Never\t");
			else
				setDurationString(difftime(time(NULL), current->rr.lastHeard), heard);
			if(current->rr.via){
				if(current->rr.statedAddress.sin6_family == AF_INET){
					addr = (struct sockaddr_in *)&current->rr.statedAddress;
					if(inet_ntop(AF_INET, &(addr->sin_addr), adrStr, sizeof adrStr) == NULL)
						strcpy(adrStr, "???");
				}else if(current->rr.statedAddress.sin6_family == AF_INET6){
					if(inet_ntop(AF_INET6, &current->rr.statedAddress.sin6_addr, adrStr, sizeof adrStr) == NULL)
						strcpy(adrStr, "???");
				}else
					strcpy(adrStr, "???");
				port = ntohs(current->rr.statedAddress.sin6_port);
			}else{
				if(current->rr.apparentAddress.sin6_family == AF_INET){
					addr = (struct sockaddr_in *)&current->rr.apparentAddress;
					if(inet_ntop(AF_INET, &(addr->sin_addr), adrStr, sizeof adrStr) == NULL)
						strcpy(adrStr, "Unknown");
				}else if(current->rr.apparentAddress.sin6_family == AF_INET6){
					if(inet_ntop(AF_INET6, &current->rr.apparentAddress.sin6_addr, adrStr, sizeof adrStr) == NULL)
						strcpy(adrStr, "Unknown");
				}else
					strcpy(adrStr, "Unknown");
				port = ntohs(current->rr.apparentAddress.sin6_port);
			}
			
			client = NULL;
			stream = NULL;
			if(current->rr.meta){
				if(item = cJSON_GetObjectItem(current->rr.meta, "Client"))
					client = item->valuestring;
				if(item = cJSON_GetObjectItem(current->rr.meta, "Stream"))
					stream = item->valuestring;
			}
			if(client == NULL)
				client = "Unknown\t";
			if(stream == NULL)
				stream = "Unknown\t";
			
			if(current->rr.m_grp)
				mgrp = current->rr.m_grp;
			else if(current->keep)
				mgrp = "Static Relay";
			else if(current->rr.via)
				mgrp = current->rr.via;
			else if(current->rr.relay){
				if(current->rr.relay_cluster){	
					snprintf(clstat, sizeof clstat, "Clu %u/%u", current->rr.relay, current->rr.relay_cluster);
					mgrp = clstat;	
				}else
					mgrp = "Relay";
			}else
				mgrp = "Direct";
			if((current->rr.relay) || (current->keep)){
				if(current->rr.m_grp == NULL)
					relay++;
			}
			snprintf(buf, sizeof buf, "%u\t%s\t%s\t%s\t%u\t%s\t%s\t%s\t%.0f/%.0f/%.0f/%.0f/%.0f\n", 
							current->UID, stream, client, adrStr, port, mgrp, 
							joined, heard, current->rr.FECStat, current->rr.ErrStat, current->rr.BadStat, current->rr.DupStat, current->rr.BalStat);
			
			appendstr(&result, buf);
			count++;
			prev = current; 
		} 
		pthread_mutex_unlock(&prev->lock);
		if(sPtr)
			pthread_mutex_unlock(&sPtr->lock);		
		else
			pthread_mutex_unlock(&cPtr->lock);
		size = snprintf(buf, sizeof buf, "%u total listeners\n", count);
		write(sd, buf, size);
		size = snprintf(buf, sizeof buf, "%u of %u relay listeners\n", rcount, limit);
		write(sd, buf, size);
		size = snprintf(buf, sizeof buf, "%u second timeout\n\n", cPtr->relay_timeout);
		write(sd, buf, size);
		size = snprintf(buf, sizeof buf, "UID\tStream\tClient\t\tAddress\t\t\tPort\ttype/via/mgrp\tJoined\tHeard\tFixed/Error/Bad/Dup/Bal\n");
		write(sd, buf, size);
		if(result){
			write(sd, result, strlen(result));
			free(result);
		}
		return;
	}
	if(strcmp(command, "reports") == 0){
		const char *source;
		char *data_str;
		struct sourceRecord *sPtr;
		cJSON *item, *report, *list;
		struct listenerNode	*prev, *current; 

		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			pthread_mutex_lock(&cPtr->lock);
			prev = cPtr->listHead;
		}else{
			if(sPtr = getSourceByName(source, cPtr->sourceList))
				prev = sPtr->listHead;
			else{
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				return;
			}
		}
		list = cJSON_CreateArray();
		pthread_mutex_lock(&prev->lock); 
		while(current = prev->link){ 
			pthread_mutex_lock(&current->lock); 
			pthread_mutex_unlock(&prev->lock);
			if(item = current->rr.meta){
				if(data_str = cJSON_PrintUnformatted(item)){
					if(report = cJSON_Parse(data_str)){
						// add connect time and ID fields
						cJSON_AddNumberToObject(report, "Joined", difftime(time(NULL), current->joined));
						cJSON_AddNumberToObject(report, "UID", current->UID);
						cJSON_AddItemToArray(list, report);
					}
					free(data_str);		
				}	
			}
			prev = current; 
		} 
		pthread_mutex_unlock(&prev->lock);
		if(sPtr)
			pthread_mutex_unlock(&sPtr->lock);
		else
			pthread_mutex_unlock(&cPtr->lock);

		report = cJSON_CreateObject();
		cJSON_AddItemToObject(report, "reports", list);
		if(data_str = cJSON_Print(report)){
			write(sd, data_str, strlen(data_str));			
			free(data_str);		
		}
		cJSON_Delete(report);		
		return;
	}	
	if(strcmp(command, "tracks") == 0){
		char *data_str;
		const char *source;
		struct sourceRecord *sPtr;
		
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			size = snprintf(buf, sizeof buf, "No source was specified.\n");
			write(sd, buf, size);
			return;
		}else{
			if((sPtr = getSourceByName(source, cPtr->sourceList)) == NULL){
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				return;
			}
			pthread_mutex_lock(&sPtr->trackLock);
			if(data_str = cJSON_Print(sPtr->trackList)){
				pthread_mutex_unlock(&sPtr->trackLock);
				size = strlen(data_str);
				write(sd, data_str, size);			
				data_str[0] = '\n';
				write(sd, data_str, 1);			
				free(data_str);
			}else{
				pthread_mutex_unlock(&sPtr->trackLock);
				size = snprintf(buf, sizeof buf, "No track data available.\n");
				write(sd, buf, size);							
			}
			pthread_mutex_unlock(&sPtr->lock);
		}
		return;
	}	
	if(strcmp(command, "metalist") == 0){
		char *data_str;
		const char *source;
		struct sourceRecord *sPtr;
		
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			size = snprintf(buf, sizeof buf, "No source was specified.\n");
			write(sd, buf, size);
			return;
		}else{
			if((sPtr = getSourceByName(source, cPtr->sourceList)) == NULL){
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				return;
			}
			if(sPtr->recode_rsp){
				pthread_mutex_lock(&sPtr->recode_rsp->metaMutex);
				if(data_str = cJSON_Print(sPtr->recode_rsp->metaRepeat)){
					pthread_mutex_unlock(&sPtr->recode_rsp->metaMutex);
					size = strlen(data_str);
					write(sd, data_str, size);			
					data_str[0] = '\n';
					write(sd, data_str, 1);			
					free(data_str);
				}else{
					pthread_mutex_unlock(&sPtr->recode_rsp->metaMutex);
					size = snprintf(buf, sizeof buf, "No repeate metadata available.\n");
					write(sd, buf, size);							
				}
			}else if(sPtr->rsp){ 
				pthread_mutex_lock(&sPtr->rsp->metaMutex);
				if(data_str = cJSON_Print(sPtr->rsp->metaRepeat)){
					pthread_mutex_unlock(&sPtr->rsp->metaMutex);
					size = strlen(data_str);
					write(sd, data_str, size);			
					data_str[0] = '\n';
					write(sd, data_str, 1);			
					free(data_str);
				}else{
					pthread_mutex_unlock(&sPtr->rsp->metaMutex);
					size = snprintf(buf, sizeof buf, "No repeate metadata available.\n");
					write(sd, buf, size);							
				}
			}else{
				size = snprintf(buf, sizeof buf, "Source has not been initialized.\n");
				write(sd, buf, size);
			}
			pthread_mutex_unlock(&sPtr->lock);
		}
		return;
	}		
	if(strcmp(command, "reset") == 0){
		const char *source;
		struct sourceRecord *sPtr;
		
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			size = snprintf(buf, sizeof buf, "No source was specified.\n");
			write(sd, buf, size);
			return;
		}else{
			if((sPtr = getSourceByName(source, cPtr->sourceList)) == NULL){
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				return;
			}
			// try reconfiguiting existing record
			if(initSourceNode(sPtr, cPtr, sPtr->source_conf) == NULL){
				// could not reconfigured existing record: try to configure a new one
				struct sourceRecord *newrec;
				if(newrec = initSourceNode(NULL, cPtr, sPtr->source_conf)){
					pthread_mutex_unlock(&sPtr->lock); 
					// OK: unlink and free old record.
					unlinkSourceNode(sPtr, cPtr->sourceList);
					freeSourceNode(sPtr, cPtr->log_listeners);
					// and link the new record into the source list
					linkSourceNode(newrec, cPtr->sourceList);
					size = snprintf(buf, sizeof buf, "Source has been re-initialized and reset.\n");
					write(sd, buf, size);
				}else{
					pthread_mutex_unlock(&sPtr->lock); 
					// Failed... do nothing
					size = snprintf(buf, sizeof buf, "Source has not been re-initialized or reset.\n");
					write(sd, buf, size);
				}
			}else{
				// existing record was reconfigured
				if((sPtr->rsp) && (sPtr->rsp->interleaver)){ 
					il_reset(sPtr->rsp->interleaver);
					size = snprintf(buf, sizeof buf, "Source has been reset.\n");
					write(sd, buf, size);
				}else{
					size = snprintf(buf, sizeof buf, "Source has not been reset.\n");
					write(sd, buf, size);
				}
				pthread_mutex_unlock(&sPtr->lock); 
			}
		}
		return;
	}		
	if(strcmp(command, "settings") == 0){
		char *data_str;
		const char *source;
		struct sourceRecord *sPtr;
		
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			size = snprintf(buf, sizeof buf, "Server Configurartion:\n");
			write(sd, buf, size);							
			pthread_mutex_lock(&cPtr->lock);
			if(data_str = cJSON_Print(cPtr->root_conf)){
				pthread_mutex_unlock(&cPtr->lock);
				size = strlen(data_str);
				write(sd, data_str, size);			
				data_str[0] = '\n';
				write(sd, data_str, 1);			
				free(data_str);
			}else{
				pthread_mutex_unlock(&cPtr->lock);
				size = snprintf(buf, sizeof buf, "No configuration available.\n");
				write(sd, buf, size);							
			}			
			return;
		}else{
			if(sPtr = getSourceByName(source, cPtr->sourceList)){
				size = snprintf(buf, sizeof buf, "\nRelay Configurartion:\n");
				write(sd, buf, size);							
				if(data_str = cJSON_Print(sPtr->source_conf)){
					size = strlen(data_str);
					write(sd, data_str, size);			
					data_str[0] = '\n';
					write(sd, data_str, 1);			
					free(data_str);
				}
				size = snprintf(buf, sizeof buf, "\nSource Configurartion:\n");
				write(sd, buf, size);				
				if(data_str = cJSON_Print(sPtr->rsp->config)){
					size = strlen(data_str);
					write(sd, data_str, size);			
					data_str[0] = '\n';
					write(sd, data_str, 1);			
					free(data_str);
				}				
				
				pthread_mutex_unlock(&sPtr->lock);
			}else{
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				return;
			}
		}
		return;
	}
	if(strcmp(command, "add") == 0){
		struct sourceRecord *sPtr;
		struct sockaddr_in6 sockAddr;
		struct sockaddr_in6 *addrPtr;
		struct listenerNode *nPtr;
		const char *type, *adrStr, *portStr, *ttlStr, *source;
		char *str;
		unsigned char no_auth;
		unsigned short portNo;
		unsigned char ttl;
		
		no_auth = 0;
		addrPtr = NULL;
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0)
			goto bad_add;
		if((sPtr = getSourceByName(source, cPtr->sourceList)) == NULL){
			size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
			write(sd, buf, size);
			return;			
		}
		type = source + strlen(source) + 1;
		if(*type == 0)
			goto bad_add;		
		adrStr = type + strlen(type) + 1;
		if(*adrStr == 0)
			goto bad_add;
		portStr = adrStr + strlen(adrStr) + 1;
		if(*portStr == 0)
			goto bad_add;

		portNo = atoi(portStr);
		if(portNo == 0)
			goto bad_add;

		ttl = 0;		
		ttlStr = portStr;
		while(1){
			ttlStr = ttlStr + strlen(ttlStr) + 1;
			if(strlen(ttlStr) == 0)
				break;
			// check for optional params
			if(strcmp(ttlStr, "NoAuth") == 0){
				no_auth = 1;
				continue;
			}
			ttl = atoi(ttlStr);
		}
		
		if(strcmp(type, "ip4") == 0){
			if(cPtr->svr_socket4 == -1)
				goto bad_add;
			addrPtr = setSockAddr(&sockAddr, FALSE, portNo, adrStr);	
		}else if(strcmp(type, "ip6") == 0){
			if(cPtr->svr_socket6 == -1)
				goto bad_add;
			addrPtr = setSockAddr(&sockAddr, TRUE, portNo, adrStr);
		}else
			goto bad_add;
		if(addrPtr){
			nPtr = newListenerNode(cPtr, NULL);		
			nPtr->authBlock = no_auth;
			bzero(&(nPtr->rr), sizeof(struct recvrRecord));
			nPtr->rr.apparentAddress = *addrPtr;
			nPtr->rr.relay = 0;	// this is not a listener requested relay
			nPtr->keep = TRUE;	// however, we will be relaying to this listener on the pre-determined port and address
			nPtr->hash = ELFHash(0, (char *)&(nPtr->rr.apparentAddress), sizeof(struct sockaddr_in6));
			if(nPtr->rr.via)
				nPtr->hash = ELFHash(nPtr->hash, nPtr->rr.via, strlen(nPtr->rr.via));
			if(ttl){
				// create a multicast socket
				if(nPtr->socket = multicastSocketSetup(cPtr, ttl) < 0){
					size = snprintf(buf, sizeof buf, "Failed to create multicast socket.\n");
					write(sd, buf, size);
					pthread_mutex_unlock(&sPtr->lock);
					freeListenerNode(nPtr, FALSE);
					return;
				}
			}
			if(linkListenerNode(sPtr->listHead, nPtr, sPtr, cPtr->log_listeners) == NULL){
				size = snprintf(buf, sizeof buf, "Relay full.\n");
				write(sd, buf, size);	
				pthread_mutex_unlock(&sPtr->lock);
				freeListenerNode(nPtr, FALSE);
				if(cPtr->log_listeners && nPtr->rr.meta && (str = cJSON_PrintUnformatted(nPtr->rr.meta))){
					syslog(LOG_INFO, "Maximum relay listeners exceeded [info=%s]", str);
					free(str);
				}
				
				return;				
			}
		}else
			goto bad_add;
		pthread_mutex_unlock(&sPtr->lock);
		return;

	bad_add:
		if(sPtr)
			pthread_mutex_unlock(&sPtr->lock);
		size = snprintf(buf, sizeof buf, "Missing or bad parameter.\n");
		write(sd, buf, size);			
		return;
	}
	
	if(strcmp(command, "delete") == 0){
		struct listenerNode	*node;
		unsigned int uid;
		char *end;
		const char *source;
		struct sourceRecord *sPtr;
		struct listenerNode *head;
		
		sPtr = NULL;
		command = command + strlen(command) + 1;
		if(*command){
			uid = strtoul(command, &end, 10);
			source = command + strlen(command) + 1;
			if(*source == 0)
				head = cPtr->listHead;
			else{
				if(sPtr = getSourceByName(source, cPtr->sourceList))
					head = sPtr->listHead;
				else{
					size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
					write(sd, buf, size);
					return;
				}
			}
			if(node = unlinkNode(NULL, head, uid))
				freeListenerNode(node, cPtr->log_listeners);
			else{
				size = snprintf(buf, sizeof buf, "Listener UID %u not found.\n", uid);
				write(sd, buf, size);	
			}
			if(sPtr)
				pthread_mutex_unlock(&sPtr->lock);			
		}
	}
	if(strcmp(command, "insert") == 0){
		char *data_str;
		const char *source, *frag;
		cJSON *obj;
		struct sourceRecord *sPtr;
		
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			size = snprintf(buf, sizeof buf, "No source was specified.\n");
			write(sd, buf, size);
			return;
		}else{
			data_str = NULL;
			// piece the null separated parameters back into a space separated string
			frag = source + strlen(source) + 1;
			while(*frag){
				appendstr(&data_str, frag);
				if(frag = frag + strlen(frag) + 1)
					appendstr(&data_str, " ");
			}
			if(data_str == NULL){
				size = snprintf(buf, sizeof buf, "Missing meta data string.\n");
				write(sd, buf, size);
				return;
			}
			if((obj = cJSON_Parse(data_str)) == NULL){
				free(data_str);
				size = snprintf(buf, sizeof buf, "Invalid jSON format for meta data string.\n");
				write(sd, buf, size);
				return;
				
			}
			free(data_str);
			if((sPtr = getSourceByName(source, cPtr->sourceList)) == NULL){
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
				cJSON_Delete(obj);
				return;
			}
			if(sPtr->recode_rsp == NULL){
				pthread_mutex_unlock(&sPtr->lock);
				size = snprintf(buf, sizeof buf, "Metadata can't be inserted: This source is not configured to reformat the originating stream.");
				write(sd, buf, size);
				cJSON_Delete(obj);
				return;
			}
			rspSessionQueueMetadata(sPtr->recode_rsp, obj, NULL);
			pthread_mutex_unlock(&sPtr->lock);
			size = snprintf(buf, sizeof buf, "Metadata has been queued.\n");
			write(sd, buf, size);
		}
		return;
	}
	if(strcmp(command, "pos") == 0){
		struct sourceRecord *prev_s, *cur_s;
		
		// travers source list
		prev_s = cPtr->sourceList;
		pthread_mutex_lock(&prev_s->lock); 
		if(prev_s->next == NULL){
			size = snprintf(buf, sizeof buf, "No Sources.\n");
			write(sd, buf, size);
		}else{
			char *tmp;
			while(cur_s = prev_s->next){ 
				pthread_mutex_lock(&cur_s->lock); 
				pthread_mutex_unlock(&prev_s->lock);
				if(cur_s->sourceName){
					if(cur_s->rsp->interleaver && il_getChecksumValid(cur_s->rsp->interleaver, cur_s->rsp->interleaver->rowBlock))
						tmp = "Auth";
					else
						tmp = "NoAuth";
					size = snprintf(buf, sizeof buf, "%s\tWrite=%.3f\tRead=%.3f\t%s\n", cur_s->sourceName, cur_s->rsp->avWrPosition, cur_s->rsp->rdPosition, tmp);
					write(sd, buf, size);
				}
				prev_s = cur_s;
			}
		}
		pthread_mutex_unlock(&prev_s->lock);
		return;
	}
	if(strcmp(command, "debug") == 0){
		const char *source;
		struct sourceRecord *sPtr;
		
		sPtr = NULL;
		source = command + strlen(command) + 1;
		if(*source == 0){
			size = snprintf(buf, sizeof buf, "No source was specified.\n");
			write(sd, buf, size);
			return;
		}else{
			if((sPtr = getSourceByName(source, cPtr->sourceList)) == NULL){
				size = snprintf(buf, sizeof buf, "Unknown source: %s\n", source);
				write(sd, buf, size);
			}else if(sPtr->rsp){
				sPtr->rsp->debugSock = sd;
				pthread_mutex_unlock(&sPtr->lock); 
				// wait for any input from the socket or an error to finish
				read(sd, buf, sizeof(buf));
			}else{
				pthread_mutex_unlock(&sPtr->lock); 
				size = snprintf(buf, sizeof buf, "Source has not been initialized.\n");
				write(sd, buf, size);
			}
		}
		return;
	}
}

int main(int argc, const char * argv[])
{
	FILE *confFile;
	int nbytes;
	struct listenerNode	*prev, *current; 
	cJSON *item;
	
	// block broken-pipe signal
	signal(SIGPIPE, SIG_IGN);
	
	if((argc > 3) && (strcmp(argv[1], "-s") == 0)){
		// pass a command to a running server via it's name socket
		struct sockaddr_un address;
		int sd;
		int i;
		char buffer[256];
		
		if((sd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
			fprintf(stderr, "Failed create a new socket.\n");
			return -1;
		}
		bzero(&address, sizeof(struct sockaddr_un));
		address.sun_family = AF_UNIX;
		strncpy(address.sun_path, argv[2], sizeof(address.sun_path));
		if(connect(sd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
			fprintf(stderr, "Failed connect to the specified socket name.\n");
			return -1;
		}
		
		for(i=3; i<argc; i++)
			// send additional parameters as NULL terminated strings
			write(sd, argv[i], strlen(argv[i])+1); // +1 to include NULL at end of string
		buffer[0] = 0;
		// send a final NULL to indicate no more parameters
		write(sd, buffer, 1);
		
		while((nbytes = read(sd, buffer, sizeof(buffer))) > 0)
			// echo result from server to standard out
			write(STDOUT_FILENO, buffer, nbytes);
		
		close(sd);
		exit(0);
	}else if((argc == 3) && (strcmp(argv[1], "-c") == 0)){
		// configure and run a server instance
	   
		// Block SIGPIPE
		sigblock(sigmask(SIGPIPE));
		
		bzero(&context, sizeof(struct serverContext));

		context.ns_socket = -1;
		context.sc_socket4 = -1;
		context.sc_socket6 = -1;
		context.svr_socket4 = -1;
		context.svr_socket6 = -1;
		context.run = TRUE;

		pthread_mutex_init(&context.lock, NULL);
		pthread_mutex_init(&context.uid_lock, NULL);
		pthread_mutex_lock(&context.uid_lock); 
		context.lastUID = 0x000000ff & getpid();	// use the process ID as the lower 8 bits of listener UIDs to help keep them unique across process re-starts
		pthread_mutex_unlock(&context.uid_lock); 
		context.sourceList = newSourceNode(&context);
		
		// Open the specified configuration file
		confFile = fopen(argv[2], "r");		
		if(confFile == NULL){
			syslog(LOG_ALERT, "Failed to open the specified configuration file.");
			fprintf(stderr, "Failed to open the specified configuration file.\n");
			return -1;
		}

		if(configureServer(confFile, &context)){
			syslog(LOG_ALERT, "Server configuration failed; shutting down.");
			fprintf(stderr, "Server configuration failed; shutting down.\n");
			fclose(confFile);
			return -1;
		}
		fclose(confFile);
		// save the file path used to configure the server
		context.conf_file = malloc(strlen(argv[2])+1);
		strcpy(context.conf_file, argv[2]);
		
		// duplicate the current stderr file discriptor, so we can manipulate stderr and then restore it.
		int err_sd;
		err_sd = dup(STDERR_FILENO);
		
		// run the control session loop
		while(context.run){
			struct sockaddr_un address;
			socklen_t length;
			char buffer[256];
			char *command;
			int sd, err_sd;
			unsigned int len;
			
			length = sizeof(struct sockaddr_un);
			while((sd = accept(context.ns_socket, (struct sockaddr *)&address, &length)) > -1){
				// new connection:  Get command and parameters and process accordingly
				command = NULL;
				len = 0;
				while((nbytes = read(sd, buffer, sizeof(buffer)-1)) > 0){
					appendbytes(&command, &len, buffer, nbytes);
					if((len > 1) && !command[len-1] && !command[len-2]){
						// reached the end of a command block (double NULL at end)
						// redirect stderr to the session socket
						dup2(sd, STDERR_FILENO);
						// process command
						processCommand(sd, &context, command);
						// restore stderr
						dup2(err_sd, STDERR_FILENO);
						free(command);
						break;
					}
				}
				shutdown(sd, SHUT_RDWR);
				close(sd);
			}
		}
		// if we get here, then the socket was closed and context.run is false, indicating we should shutdown
		if(context.svr_socket4 > -1){ 
			shutdown(context.svr_socket4, SHUT_RDWR);
			close(context.svr_socket4);
		}
		context.svr_socket4 = -1;
		if(context.svr_socket6 > -1){ 
			shutdown(context.svr_socket6, SHUT_RDWR);
			close(context.svr_socket6);
		}
		context.svr_socket6 = -1;
		if(context.sc_socket4 > -1){
			shutdown(context.sc_socket4, SHUT_RDWR);
			close(context.sc_socket4);
		}
		context.sc_socket4 = -1;
		if(context.sc_socket6 > -1){ 
			shutdown(context.sc_socket6, SHUT_RDWR);
			close(context.sc_socket6);
		}
		context.sc_socket6 = -1;
		if(item = cJSON_GetObjectItem(context.root_conf, "controlSocket")){
			if(item->valuestring && strlen(item->valuestring))
				unlink(item->valuestring);
		}
		if(context.reportV4_thread){
			pthread_cancel(context.reportV4_thread);
			pthread_join(context.reportV4_thread, NULL);
		}
		if(context.reportV6_thread){
			pthread_cancel(context.reportV6_thread);
			pthread_join(context.reportV6_thread, NULL);
		}
		if(context.scListen4_thread){
			pthread_cancel(context.scListen4_thread);
			pthread_join(context.scListen4_thread, NULL);
		}
		if(context.scListen6_thread){
			pthread_cancel(context.scListen6_thread);
			pthread_join(context.scListen6_thread, NULL);
		}

		if(context.rep_rsp)
			// close out our rsp session
			rspSessionFree(context.rep_rsp);
		
		// destroy non-source listeners linked list
		// we ignore mutext locks, as all threads should have ended by now
		current = context.listHead;
		while(prev = current){
			current = prev->link;
			freeListenerNode(prev, context.log_listeners);
		}
		
		// delete sourceRecords
		if(context.sourceList){
			struct sourceRecord *rec;
			while(rec = context.sourceList->next){
				if(rec = unlinkSourceNode(rec, context.sourceList))
					freeSourceNode(rec, context.log_listeners);
			}
			context.sourceList = NULL;
		}
		
		if(context.relay_identity)
			free(context.relay_identity);
		if(context.sc_identity)
			free(context.sc_identity);
		if(context.sc_default)
			free(context.sc_default);
		if(context.conf_file)
			free(context.conf_file);
		pthread_mutex_destroy(&context.lock);
		pthread_mutex_destroy(&context.uid_lock);
		if(context.root_conf)
			cJSON_Delete(context.root_conf);
		
		return 0;		
	
	}else{
		fprintf(stdout, "Usage:\n\nrspServer -c /server/config/file/path\n");
		fprintf(stdout, "\nStarts an instance of rspServer configured using the specified configurstion file\n");
		fprintf(stdout, "in jSON format.  See example file(should have been included with this program).\n");
		fprintf(stdout, "\nrspServer -s /named/socket/of/running/rspServer/path addditional arguments\n");
		fprintf(stdout, "\nConnects to a running rspServer server instance via the specified named socket,\n");
		fprintf(stdout, "passing the additional arguments to the server.  The named socket of the server\n");
		fprintf(stdout, "is configured with the controlSocket parameter of the servers configurtion file.\n");
		fprintf(stdout, "Currently supported additional arguments are:\n\n");
		fprintf(stdout, "shutdown\n\tStops the server from running\n\n");
		fprintf(stdout, "reload /server/config/file/path\n\tReloads the server configuration, trying to keep connections open when possible.\n\n");
		fprintf(stdout, "status\n\tShows server status and lists all the sources being relayed (RSP and/or Shoutcast) by this server.\n\n");
		fprintf(stdout, "pos\n\tLists the current read/write interleaver posisions of all the sources being relayed by this server.\n\n");
		fprintf(stdout, "list (source_name)\n\tshows the status of all current listeners either reporting or for the specified source\n\n");
		fprintf(stdout, "reports (source_name)\n\tjSON dump of all current listeners' report data either reporting or for the specified source.\n\n");
		fprintf(stdout, "tracks source_name\n\tshows a jSON array of the last 10 tracks relayed through this server\n\n");
		fprintf(stdout, "metalist source_name\n\tshows a jSON array of all the repeate metadata items currently active for thsi source.\n\n");
		fprintf(stdout, "settings (source_name)\n\tshows configuration settings this server was loaded with or the setting for the specified source.\n\n");
		fprintf(stdout, "reset source_name\n\tResets the specified source's interleaver.\n\n");
		fprintf(stdout, "delete listener-UID (source_name)\n\tremoves (and stops relaying to) the specified listener for either the specified source.\n\n");
		fprintf(stdout, "add source_name [ip4][ip6] Addr PortNo (mcast ttl) (NoAuth)\n\tAdds a static unicast RSP relay listener (if relaying is enabled)\n\n");
		fprintf(stdout, "insert source_name jSON-string\n\tInserts the specified jSON string in non-printing (no LF/CR)\n");
		fprintf(stdout, "\tformat, into the specified source's **re-formated** rsp metadata stream.  This has no effect for non-reformated relays.\n\n");
		return 0;		
	}
}
