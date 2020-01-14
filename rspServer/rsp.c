/*
 
 Copyright (c) 2015 Ethan Funk
 
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

#include <sys/time.h>
#include <math.h>
#include "rsp.h"
#include "rs.h"

#ifdef __APPLE__
	#include <malloc/malloc.h>
#endif

// Handy utility functions

void timespec_diff(struct timespec *start, struct timespec *end, struct timespec *diff){
	if ((end->tv_nsec - start->tv_nsec) < 0) {
		diff->tv_sec = end->tv_sec - start->tv_sec - 1;
		diff->tv_nsec = 1000000000 + end->tv_nsec - start->tv_nsec;
	} else {
		diff->tv_sec = end->tv_sec - start->tv_sec;
		diff->tv_nsec = end->tv_nsec - start->tv_nsec;
	}
}

void appendstr(char **string, const char *cStr)
{
	int size;
	
	if(cStr == NULL)
		return;
	size = strlen(cStr) + 1;
	if(*string == NULL)
		*string = calloc(1, size);
	size = strlen(*string) + size;
	*string = realloc(*string, size);
	strcat(*string, cStr);
}

void appendchr(char **string, char chr)
{
	int size;
	char str[2]; 
	
	if(chr == 0)
		return;
	str[0] = chr;
	str[1] = 0;
	size = 2;
	if(*string == NULL)
		*string = calloc(1, size);
	size = strlen(*string) + size;
	*string = realloc(*string, size);
	strcat(*string, str);
}

// rsp functions
float rspVersion(const char **vStr)
{
	if(vStr) 
		*vStr = "1.5";
	return 1.5;
}

ssize_t rspSendto(int socket, const void *data, size_t size, int flags, const struct sockaddr *addr)
{
	// one function to handle the size of both IPv4 and IPv6 addresses
	if(addr->sa_family == AF_INET6)
		return sendto(socket, data, size, flags, addr, sizeof(struct sockaddr_in6));
	else
		return sendto(socket, data, size, flags, addr, sizeof(struct sockaddr_in));
}

unsigned int ELFHash(unsigned int hash, char* str, unsigned int len)
{
	unsigned int x;
	unsigned int i;
	
	for(i = 0; i < len; str++, i++){
		hash = (hash << 4) + (*str);
		if((x = hash & 0xF0000000L) != 0){
			hash ^= (x >> 24);
		}
		hash &= ~x;
	}
	return hash;
}

struct rspSession *rspSessionNew(const char *clientName)
{
	if((clientName == NULL) || !strlen(clientName))
		return NULL;
		
	struct rspSession *session;
	
	session = (struct rspSession *)calloc(1, sizeof(struct rspSession));
	// non-zero initial settings
	chksum_crc32gentab(session->crc_table);
	session->clientSocket = -1;
	session->debugSock = -1;
	session->wrRate = -1.0;
	session->timeout = 10;
	session->interleaving = 1;
	session->extCount = 250;	// set for 5 reset packets initially (255 - 5)
	session->clientName = (char *)malloc(strlen(clientName)+1);
	strcpy(session->clientName, clientName);
	session->metaRepeat = cJSON_CreateObject();
	// created a session mutex for mutual exclution control if the session is to be accessed
	// simaltainiously from multiple threads
	pthread_mutex_init(&session->threadLock, NULL);
	pthread_mutex_init(&session->metaMutex, NULL);
		
	return session;
}

cJSON *rspSessionReadConfigFile(FILE *fd)
{
	long len;
	char *data;
	cJSON *root, *rspSection;
	
	fseek(fd, 0, SEEK_END);
	len = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	
	data = (char *)malloc(len + 1);
	data[len] = 0;
	fread(data, 1, len, fd);
	if((root = cJSON_Parse(data)) == NULL){
		free(data);
		return NULL;
	}
	free(data);
	
	// if there is an rspStream object in the top level, use that object
	// otherwise assume the top level object it self contains the configuration info.
	if((rspSection = cJSON_DetachItemFromObject(root, "rspStream")) == NULL)
		rspSection = root;
	else
		cJSON_Delete(root);
	return rspSection;
}

unsigned char rspSessionConfigNextJSON(struct rspSession *session, cJSON **rspObjHandle)
{
	char *tmpStr;
	cJSON *item;
	cJSON *format;
	cJSON *rspObj;
	
	// Pass in a handle to a cJSON "rspStream" object with which to configure the passed rspSession.
	// If the passed rspStream handle is a list, the first item in the list will be used for configuration
	// and the handle will be set to the next item on in the list.  Subsequent calls with the same handle passed in
	// will itterate through the list until there are no more list items.  In this case RSP_ERROR_END is returned.
	
	if((rspObj = *rspObjHandle) == NULL)
		return RSP_ERROR_END;
	
	if(!cJSON_strcasecmp(rspObj->string,"rspStream")){
		// either a a single rspStream container or the root of a list of conatiners
		if(rspObj->type == cJSON_Array){
			// root of a list: get first object in array
			if((rspObj = rspObj->child) == NULL){
				// An empty list: no next in list item and return error.
				*rspObjHandle = NULL;
				return RSP_ERROR_END;
			}
			// not empty... we have our first object
			*rspObjHandle =rspObj->next;
		}else
			// single container... No next in list item
			*rspObjHandle = NULL;
		
	}else{
		// this is another one in a list
		*rspObjHandle =rspObj->next;
	}
	
	// make a copy of the object so we own the copy.
	if(tmpStr = cJSON_PrintUnformatted(rspObj)){
		rspObj = cJSON_Parse(tmpStr);
		free(tmpStr);
		if(rspObj == NULL)
			return RSP_ERROR_PARSING;
	}else{
		return RSP_ERROR_PARSING;
	}
	
	if((item = cJSON_GetObjectItem(rspObj, "Name")) && (item->valuestring)){
		session->streamName = (char *)malloc(strlen(item->valuestring)+1);
		strcpy(session->streamName, item->valuestring);
	}
	
	// Format properties... not required for receiving: Format can be discovered by listening to incoming packets
	// This is useful for configuring an encoder
	if(format = cJSON_GetObjectItem(rspObj, "Format")){
		if(item = cJSON_GetObjectItem(format, "FEC"))
			session->FECroots = item->valueint;
		else
			session->FECroots = 0;
		
		if(item = cJSON_GetObjectItem(format, "Interleave"))
			session->interleaving = item->valueint;
		else
			session->interleaving = 1;
		
		if(item = cJSON_GetObjectItem(format, "Payload"))
			session->colSize = item->valueint;
		else
			session->colSize = 0;
		
		session->flags = 0;
		if(item = cJSON_GetObjectItem(format, "CRC"))
			if(item->valueint) session->flags |= RSP_FLAG_CRC;
		if(item = cJSON_GetObjectItem(format, "RS"))
			if(item->valueint) session->flags |= RSP_FLAG_RS;

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
		// For backward compatiblility, the public key COULD be in the format section.  Try to AVOID this! 
		if(item = cJSON_GetObjectItem(format, "RSAPublicKey")){
			if(item->valuestring && rspSessionSetPubKeyString(session, item->valuestring)){
				cJSON_Delete(rspObj);
				return RSP_ERROR_MISSING;
			}
		}
#endif
        
	}

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	// the public key SHOULD be in root object, if it is set at all.
	if(item = cJSON_GetObjectItem(rspObj, "RSAPublicKey")){
		if(item->valuestring && rspSessionSetPubKeyString(session, item->valuestring)){
			cJSON_Delete(rspObj);
			return RSP_ERROR_MISSING;
		}
	}
#endif
    
	session->triedIP6 = FALSE;
	if(session->config)
		cJSON_Delete(session->config);
	session->config = rspObj;

	return RSP_ERROR_NONE;
}

unsigned char rspSessionInit(struct rspSession *session)
{
	unsigned char netRS;

	if((session->FECroots > 127) || (session->FECroots < 2))
		return RSP_ERROR_INIT;
	if((session->interleaving < 1) || (session->interleaving > 85))
		return RSP_ERROR_INIT;
	if((session->colSize < 16) || (session->colSize > 256))
		return RSP_ERROR_INIT;
	if((session->flags & RSP_FLAG_RS) && (session->colSize > 224))
		return RSP_ERROR_INIT;
	if(session->colSize & 0x0F)		// not an integer multiple of 16
		return RSP_ERROR_INIT;
		
	if(rspPacketInit(session->rsp_packet, session->flags, session->colSize, &netRS) == 0)
		return RSP_ERROR_INIT;
	
	if(session->flags & RSP_FLAG_RS){
		// initialize a Reed-Solomon(255, x) session for network packets
		// value of x is determined by packet options and is set by the pervious rspPacketInit call
		if((session->network_rs = init_rs_char(8, 0x11d, 1, 1, 255 - netRS)) == NULL)
			return RSP_ERROR_INIT;
	}
	// initialize a Reed-Solomon(255, FECroots) session for audio packets
	if((session->audio_rs = init_rs_char(8, 0x11d, 1, 1, session->FECroots)) == NULL)
		return RSP_ERROR_INIT;
	session->interleaver = il_init(session->colSize, 255, session->interleaving);
	
	// Avr time constant = 0.1 buffer
	session->rowScaling = 10.0 * M_E / (session->interleaver->rows * session->interleaver->ratio);
	session->columnScaling = 10.0 * M_E / (session->interleaver->columns * session->interleaver->ratio);
	
	return RSP_ERROR_NONE;
}

void rspSessionClear(struct rspSession *session, unsigned char close_net)
{
	if(close_net){
		if(session->clientSocket > -1)
			close(session->clientSocket);
		bzero(&session->bindAddr, sizeof(struct sockaddr_in6));
		bzero(&session->rrAddr, sizeof(struct sockaddr_in6));
		bzero(&session->rrAddr2, sizeof(struct sockaddr_in6));
		if(session->clusterList){
			free(session->clusterList);
			session->clusterList = NULL;
		}
		session->relay_cluster = 0;
		session->relay = 0;
		session->rrPeriod = 0;
		session->lastReport = 0;
		session->clientSocket = -1;
	}
	
	if(session->debugSock > -1){
		close(session->debugSock);
		session->debugSock = -1;
	}
	if(session->network_rs)
		free_rs_char(session->network_rs);
	session->network_rs = NULL;
	if(session->audio_rs)
		free_rs_char(session->audio_rs);
	session->audio_rs = NULL;
	if(session->interleaver)
		il_free(session->interleaver);
	session->interleaver = NULL;
	while(session->rdQueIdx != session->wrQueIdx){
		// free any unprocessed meta data records
		cJSON_Delete(session->metaQueue[session->rdQueIdx]);
		session->rdQueIdx = (session->rdQueIdx + 1) & 0x0F;
	}

	session->wrQueIdx = 0;
	session->rdQueIdx = 0;
	session->repeateIndex = 0;
	
	session->avWrPosition = 0.0;
	session->lastWrPos = 0.0;

	session->rdPosition = 0.0;
	session->wrRate = -1.0;
	session->playing = FALSE;
	
	bzero(&session->lastRdTime, sizeof(struct timespec));
	bzero(&session->lastWrTime, sizeof(struct timespec));
	
	session->extCount = 250;	// set to send 5 reset packets initially when reading packets for transmission
	
	if(session->metaString)
		free(session->metaString);
	session->metaString = NULL;
	session->metaCorrupt = FALSE;

	if(session->metaRepeat)
		cJSON_Delete(session->metaRepeat);
	session->metaRepeat = cJSON_CreateObject();
	session->ext_header[0] = 0;
	session->ext_header[1] = 0;
	session->ext_header[2] = 0;
	session->ext_header[3] = 0;
	session->ext_header[4] = 0;
}

void rspSessionFree(struct rspSession *session)
{
	rspSessionClear(session, TRUE);
	if(session->metaString)
		free(session->metaString);
	if(session->config)
		cJSON_Delete(session->config);
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	if(session->rsaPub)
		RSA_free(session->rsaPub);
	if(session->rsaPriv)
		RSA_free(session->rsaPriv);
#endif
	if(session->clientName)
		free(session->clientName);
	if(session->streamName)
		free(session->streamName);
	if(session->metaRepeat)
		cJSON_Delete(session->metaRepeat);
	session->metaRepeat = NULL;	
	
	if(session->dnsList.h_addr_list){
		free(session->dnsList.h_addr_list);
		session->dnsList.h_addr_list = NULL;
	}
	pthread_mutex_destroy(&session->metaMutex);
	pthread_mutex_destroy(&session->threadLock);

	free(session);
}

unsigned char rspSessionNextNetworkSetup(struct rspSession *session, unsigned int nwTimeout, char *bindTo)
{
	// This function will return with the rspSession network setup to receive a stream from the next available network
	// configuration using a DNS resolution list if the current session address is non-numeric.  Otherwise the single 
	// numeric address is used. The session IP6 section is tried first, then the IPv4 section.
	
	// When a stream address doesn't play, you can loop back and call this function to try more dns entries for a 
	// named address of a given IP4/IP6 section until no more dns entries and IP sections exist to try, causing 
	// RSP_ERROR_END to be returned.
	
	cJSON *item;
	unsigned char status;
	
	if(!session->triedIP6){
		// first try an IP6 record
		if(item = cJSON_GetObjectItem(session->config, "IP6")){
			// Loop until we have tried all DNS entries
			while((status = rspSessionNetworkSetup(item, session, nwTimeout, bindTo)) == RSP_ERROR_INIT);
			if(status == RSP_ERROR_NONE)
				return status;
			if(status == RSP_ERROR_END)
				session->triedIP6 = TRUE;
		}else{
			session->triedIP6 = TRUE;	
		}
	}
	// then try an IP4 record
	if(item = cJSON_GetObjectItem(session->config, "IP4")){
		// Loop until we have tried all DNS entries
		while((status = rspSessionNetworkSetup(item, session, nwTimeout, bindTo)) == RSP_ERROR_INIT);
		if(status == RSP_ERROR_NONE)
			return status;
	}
	return RSP_ERROR_END;
}

unsigned char rspSessionNetworkSetup(cJSON *group, struct rspSession *session, unsigned int nwTimeout, char *bindTo)
{	
	cJSON *item;
	unsigned char status;
	int port, rr_port, rr_port2, result;
	unsigned int size;
	char *rr_host, *rr_host2;
	struct timeval tv;
	struct sockaddr_in *rrAddr;
	struct sockaddr_in *bindAddr;
	struct in6_addr v6bindto;
	u_int32_t v4bindto;
	struct hostent *host;			// host/IP translation
	char *ptr;				// pointer to allocated data area, just past the pointer array
	int i;
	
	rr_host = NULL;
	rr_port = 0;
	rr_host2 = NULL;
	rr_port2 = 0;
	port = 0;
	
	size = sizeof(struct sockaddr_in6);
	bzero(&session->bindAddr, size);
	bzero(&session->rrAddr, size);	
	bzero(&session->rrAddr2, size);
	bzero(&session->lastRdTime, sizeof(struct timeval));
	bzero(&session->lastWrTime, sizeof(struct timeval));
	
	if(session->clientSocket >= 0){
		close(session->clientSocket);
		session->clientSocket = -1;
	}
	session->rrPeriod = 0;
	// common to IPv4 and IPv6
	if(item = cJSON_GetObjectItem(group, "Port"))
		port = item->valueint;
	session->relay = 1;
	if(port)
		session->relay = 0;
	if(item = cJSON_GetObjectItem(group, "MulticastGroup"))
		session->m_grp = item->valuestring;
	if(session->m_grp && strlen(session->m_grp))
		session->relay = 0;
	
	// If "Relay" property is specifically set, allow it to override default behavior
	// (Non-zero Port or MulticastGroup settings cause Relay = 0, otherwise = 1).  This is 
	// usefull if you want to setup a listener to receive BOTH a static relay on a specific
	// port and to also have it request a duplicated relay stream via the specified ReportHost.
	if(item = cJSON_GetObjectItem(group, "Relay")){
		if(item->type == cJSON_True)
			session->relay = 1;
		if(item->type == cJSON_False)
			session->relay = 0;
		if(item->type == cJSON_Number){
			if(item->valueint)
				session->relay = 1;
			else
				session->relay = 0;
		}
	}
	
	if(item = cJSON_GetObjectItem(group, "ReportPort"))
		rr_port = item->valueint;
	if(item = cJSON_GetObjectItem(group, "ReportHost"))
		rr_host = item->valuestring;
	if(item = cJSON_GetObjectItem(group, "ReportPortSec"))
		rr_port2 = item->valueint;
	if(item = cJSON_GetObjectItem(group, "ReportHostSec"))
		rr_host2 = item->valuestring;
	if(item = cJSON_GetObjectItem(group, "ReportPeriod"))
		session->rrPeriod = item->valueint;
		
	// for IPv6 only
	if(!cJSON_strcasecmp(group->string, "IP6")){
		// IPv6 network settings found
		if((session->clientSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0){
			status = RSP_ERROR_END; 
			goto fail;
		}
		// set receive time out, so we can check for rr record send time in
		// the same loop that receives packets with out blocking for more than 1 second.
		if(session->rrPeriod && (session->rrPeriod < nwTimeout))
			nwTimeout = session->rrPeriod;
		tv.tv_sec = nwTimeout;  
		tv.tv_usec = 0;  
		if(setsockopt(session->clientSocket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) < 0){
			status = RSP_ERROR_END; 
			goto fail;
		}
		
		if(bindTo){
			if((result = inet_pton(AF_INET6, bindTo, &v6bindto)) <= 0){
				status = RSP_ERROR_END; 
				goto fail;
			}
		}else
			v6bindto = in6addr_any;
#ifndef __linux__
		session->rrAddr.sin6_len = sizeof(struct sockaddr_in6);
		session->rrAddr2.sin6_len = sizeof(struct sockaddr_in6);		
#endif	
		session->reportToSource = FALSE;
		if(rr_host && (strcasecmp(rr_host, "source") == 0)){
			session->reportToSource = TRUE;
		}else if(rr_host && (rr_port > 0)){
			// will be sending any receiver reports and/or start/stop unicast stream requests
			// set up an address record...
			// First try the address as doted-quad format
			if((result = inet_pton(AF_INET6, rr_host, &session->rrAddr.sin6_addr)) < 0){
				status = RSP_ERROR_END; 
				goto fail;
			}
			if(result == 0){
				if(session->dnsList.h_addr_list == NULL){
					// Otherwise, look up name					
					if((host = gethostbyname2(rr_host, AF_INET6)) == NULL){
						status = RSP_ERROR_END; 
						goto fail;
					}
					// copy the address list from host to our own record in list otherwise
					// subsequent calls to gethostbyname2 might write over the data 
					// returned in host while we are still using it 
					i = 0;
					// count list entries
					while(host->h_addr_list[i])
						i++;
					if(i == 0){
						status = RSP_ERROR_END; 
						goto fail;
					}
					// allocate memory for pointer array with null termination and the data pointed to in that array.
					// this is a single allocation holding the pointer list with last NULL entry followed by the actual data.
					session->dnsList.h_size = host->h_length;
					session->dnsList.h_addr_list = (char **)malloc(i * (sizeof(char *) + host->h_length) + sizeof(char *));
					// null terminate the pointer list
					session->dnsList.h_addr_list[i] = NULL;
					session->dnsList.h_index = -1;
					// note where the pointer list ends; This is the start of the data area
					ptr = (char *)&session->dnsList.h_addr_list[i+1];
					// copy each entry from the host record to our data area, setting 
					// the corisponding pointer to the associated data area location 
					i = 0;
					while(host->h_addr_list[i]){
						// copy data
						memcpy(ptr, host->h_addr_list[i], session->dnsList.h_size);
						// set pointer in list
						session->dnsList.h_addr_list[i] = ptr;
						// increment data pointer to next data slot
						ptr = ptr + host->h_length;
						// increment pointer list index
						i++;
					}
				}
				// move to next dsn record in list (if any)
				session->dnsList.h_index++;
				if(session->dnsList.h_addr_list[session->dnsList.h_index] == NULL){
					// reached the end of the list of DNS address list
					free(session->dnsList.h_addr_list);
					session->dnsList.h_addr_list = NULL;
					status = RSP_ERROR_END; 
					goto fail;				
				}
				// We have a resolved address!
				memcpy(&session->rrAddr.sin6_addr, session->dnsList.h_addr_list[session->dnsList.h_index], session->dnsList.h_size);
			}
			session->rrAddr.sin6_family = AF_INET6;
			session->rrAddr.sin6_port = htons(rr_port);
		}
		
		if(rr_host2 && (rr_port2 > 0)){
			// will be sending receiver secondary reports and/or start/stop unicast stream requests
			// set up an address record...
			// First try the address as numeric format
			if((result = inet_pton(AF_INET6, rr_host, &session->rrAddr2.sin6_addr)) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			if(result == 0){
				// Otherwise, look up name
				host = gethostbyname2(rr_host2, AF_INET6);
				if(host == NULL) {
					status = RSP_ERROR_INIT; 
					goto fail;
				}
				// We have a resolved address!
				memcpy(&session->rrAddr2.sin6_addr, host->h_addr_list[0], host->h_length);
			}
			session->rrAddr2.sin6_family = AF_INET6;
			session->rrAddr2.sin6_port = htons(rr_port);
		}
#ifndef __linux__
		session->bindAddr.sin6_len = sizeof(struct sockaddr_in6);
#endif	
		if(session->m_grp && strlen(session->m_grp)){
			if(port <= 0){
				// multicast needs a port specified... fail
				status = RSP_ERROR_END; 
				goto fail;
			}
			
			struct ipv6_mreq mreq;
			unsigned int yes=1;  
			
			// allow multiple sockets to use the same PORT number
			if(setsockopt(session->clientSocket, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(yes)) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// bind to port
			session->bindAddr.sin6_family = AF_INET6;
			session->bindAddr.sin6_addr = v6bindto;
			session->bindAddr.sin6_port = htons(port);
			size = sizeof(struct sockaddr_in);
			if(bind(session->clientSocket, (struct sockaddr *)&session->bindAddr, size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// find out what address/port was assigned
			size = sizeof(struct sockaddr_in6);
			if (getsockname(session->clientSocket, (struct sockaddr *)&session->bindAddr, &size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// use setsockopt() to request that the kernel join a multicast group */
			if((result = inet_pton(AF_INET6, session->m_grp, &mreq.ipv6mr_multiaddr)) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			if(result == 0){
				// Otherwise, look up name
				host = gethostbyname2(session->m_grp, AF_INET6);
				if(host == NULL){ 
					status = RSP_ERROR_INIT; 
					goto fail;
				}
				memcpy(&mreq.ipv6mr_multiaddr, host->h_addr_list[0], host->h_length);
			}
			mreq.ipv6mr_multiaddr = v6bindto;
			if(setsockopt(session->clientSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0){		
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
		}else{
			if(port < 0)
				port = 0;
			// unicast port specified: bind to port
			session->bindAddr.sin6_family = AF_INET6;
			session->bindAddr.sin6_addr = v6bindto;
			session->bindAddr.sin6_port = htons(port);
			size = sizeof(struct sockaddr_in);
			if(bind(session->clientSocket, (struct sockaddr *)&session->bindAddr, size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// find out what address/port was assigned
			size = sizeof(struct sockaddr_in6);
			if (getsockname(session->clientSocket, (struct sockaddr *)&session->bindAddr, &size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			if(!port &&(!rr_host || (rr_port <= 0))){
				// no unicast port specified, and no receiver request sending: This can't work - fail.
				status = RSP_ERROR_INIT; 
				goto fail;
			}
		}		
	}else if(!cJSON_strcasecmp(group->string, "IP4")){
		// look for old (IPv4) network settings
		if((session->clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0){
			status = RSP_ERROR_END; 
			goto fail;
		}
		// set receive time out, so we can check for rr record send time in
		// the same loop that receives packets with out blocking for more than 1 second.
		if(session->rrPeriod && (session->rrPeriod < nwTimeout))
			nwTimeout = session->rrPeriod;
		tv.tv_sec = nwTimeout;  
		tv.tv_usec = 0;  
		if(setsockopt(session->clientSocket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) < 0){
			status = RSP_ERROR_END; 
			goto fail;
		}

		if(bindTo){
			if((result = inet_pton(AF_INET, bindTo, &v4bindto)) <= 0)
				v4bindto = INADDR_ANY;
		}else
			v4bindto = INADDR_ANY;
		
		rrAddr = (struct sockaddr_in *)&session->rrAddr;
#ifndef __linux__
		rrAddr->sin_len = sizeof(struct sockaddr_in);
#endif	
		rrAddr->sin_family = AF_INET;
		rrAddr->sin_port = htons(rr_port);
		session->reportToSource = FALSE;
		if(rr_host && (strcasecmp(rr_host, "source") == 0)){
			session->reportToSource = TRUE;
		}else if(rr_host && (rr_port > 0)){
			// will be sending any receiver reports and/or start/stop unicast stream requests
			// set up an address record...
			// First try the address as doted-quad format
			if((result = inet_pton(AF_INET, rr_host, &rrAddr->sin_addr.s_addr)) < 0){
				status = RSP_ERROR_END; 
				goto fail;
			}else if(result > 0){
				if(session->dnsList.h_index == -1){
					// already tried this numeric address
					status = RSP_ERROR_END; 
					goto fail;	
				}else
					// flag that we tried this address... fill set error_end next time through (see above)
					session->dnsList.h_index = -1;
			}else{
				if(session->dnsList.h_addr_list == NULL){
					// Otherwise, look up name
					struct hostent *host;			// host/IP translation
					char *ptr;						// pointer to allocated data area, just past the pointer array
					int i;
					
					if((host = gethostbyname2(rr_host, AF_INET)) == NULL){
						status = RSP_ERROR_END; 
						goto fail;
					}
					// copy the address list from host to our own record in list otherwise
					// subsequent calls to gethostbyname2 might write over the data 
					// returned in host while we are still using it 
					i = 0;
					// count list entries
					while(host->h_addr_list[i])
						i++;
					if(i == 0){
						status = RSP_ERROR_END; 
						goto fail;
					}
					// allocate memory for pointer array with null termination and the data pointed to in that array.
					// this is a single allocation holding the pointer list with last NULL entry followed by the actual data.
					session->dnsList.h_size = host->h_length;
					session->dnsList.h_addr_list = (char **)malloc(i * (sizeof(char *) + host->h_length) + sizeof(char *));
					// null terminate the pointer list
					session->dnsList.h_addr_list[i] = NULL;
					session->dnsList.h_index = -1;
					// note where the pointer list ends; This is the start of the data area
					ptr = (char *)&session->dnsList.h_addr_list[i+1];
					// copy each entry from the host record to our data area, setting 
					// the corisponding pointer to the associated data area location 
					i = 0;
					while(host->h_addr_list[i]){
						// copy data
						memcpy(ptr, host->h_addr_list[i], session->dnsList.h_size);
						// set pointer in list
						session->dnsList.h_addr_list[i] = ptr;
						// increment data pointer to next data slot
						ptr = ptr + host->h_length;
						// increment pointer list index
						i++;
					}
				}
				// move to next dsn record in list (if any)
				session->dnsList.h_index++;
				if(session->dnsList.h_addr_list[session->dnsList.h_index] == NULL){
					// reached the end of the list of DNS address list
					free(session->dnsList.h_addr_list);
					session->dnsList.h_addr_list = NULL;
					status = RSP_ERROR_END; 
					goto fail;				
				}
				// We have a resolved address!
				memcpy(&rrAddr->sin_addr.s_addr, session->dnsList.h_addr_list[session->dnsList.h_index], session->dnsList.h_size);
			}
		}
		
		rrAddr = (struct sockaddr_in *)&session->rrAddr2;
#ifndef __linux__
		rrAddr->sin_len = sizeof(struct sockaddr_in);		
#endif	
		if(rr_host2 && (rr_port2 > 0)){
			// will be sending any receiver reports and/or start/stop unicast stream requests
			// set up an address record...
			// First try the address as doted-quad format
			if((result = inet_pton(AF_INET, rr_host2, &rrAddr->sin_addr.s_addr)) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			if(result == 0){
				// Otherwise, look up name
				host = gethostbyname2(rr_host2, AF_INET);
				if(host == NULL) {
					status = RSP_ERROR_INIT; 
					goto fail;
				}
				// We have a resolved address!
				memcpy(&rrAddr->sin_addr.s_addr, host->h_addr_list[0], host->h_length);
			}
			rrAddr->sin_family = AF_INET;
			rrAddr->sin_port = htons(rr_port2);
		}
		bindAddr = (struct sockaddr_in *)&session->bindAddr;
#ifndef __linux__
		bindAddr->sin_len = sizeof(struct sockaddr_in);
#endif	
		if(session->m_grp && strlen(session->m_grp)){
			if(port <= 0){
				// multicast needs a port specified... fail
				status = RSP_ERROR_END; 
				goto fail;
			}
			
			struct ip_mreq mreq;
			unsigned int yes=1;  
			
			// allow multiple sockets to use the same PORT number
			if(setsockopt(session->clientSocket, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(yes)) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// bind to port
			bindAddr->sin_family = AF_INET;
			bindAddr->sin_addr.s_addr = v4bindto;
			bindAddr->sin_port = htons(port);
			size = sizeof(struct sockaddr_in);
			if(bind(session->clientSocket, (struct sockaddr *)bindAddr, size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			
			// find out what address/port was assigned
			size = sizeof(struct sockaddr_in);
			if (getsockname(session->clientSocket, (struct sockaddr *)bindAddr, &size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// use setsockopt() to request that the kernel join a multicast group */
			if((result = inet_pton(AF_INET, session->m_grp, &mreq.imr_multiaddr.s_addr)) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			if(result == 0){
				// Otherwise, look up name
				host = gethostbyname2(session->m_grp, AF_INET);
				if(host == NULL){ 
					status = RSP_ERROR_INIT; 
					goto fail;
				}
				memcpy(&mreq.imr_multiaddr.s_addr, host->h_addr_list[0], host->h_length);
			}
			mreq.imr_interface.s_addr = v4bindto;
			if(setsockopt(session->clientSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0){		
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
		}else{
			if(port < 0)
				port = 0;
			// unicast port specified: bind to port
			bindAddr->sin_family = AF_INET;
			bindAddr->sin_addr.s_addr = v4bindto;
			bindAddr->sin_port = htons(port);
			size = sizeof(struct sockaddr_in);
			if(bind(session->clientSocket, (struct sockaddr *)bindAddr, size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			// find out what address/port was assigned
			size = sizeof(struct sockaddr_in);
			if(getsockname(session->clientSocket, (struct sockaddr *)bindAddr, &size) < 0){
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
			if(!port &&(!rr_host || (rr_port <= 0))){
				// no unicast port specified, and no receiver request sending: This can't work - fail.
				status = RSP_ERROR_INIT; 
				goto fail;
			}
			
		}
	}else{
		status = RSP_ERROR_END; 
		goto fail;
	}
			 
	return RSP_ERROR_NONE;
			 
fail:
	 session->dnsList.h_index = 0;
	 size = sizeof(struct sockaddr_in6);
	 bzero(&session->bindAddr, size);
	 bzero(&session->rrAddr, size);	
	 bzero(&session->rrAddr2, size);	
	 if(session->clientSocket > -1)
		 close(session->clientSocket);
	 session->clientSocket = -1;
	 session->rrPeriod = 0;
	 return status;	
}
		 
void rspSessionClusterSetup(struct rspSession *session, cJSON *relayCluster)
{					   
	struct sockaddr_in6 bindAddr;
	unsigned int size, uindex;
	time_t now;
	int index, portno, result;
	char *copy, *host, *portstr;
	cJSON *item;
	cJSON *group;
	unsigned char IPv6;
	unsigned char sendstop, removed;
	struct clusterRecord *newList, *rec, *prev, *old;
	struct hostent *hostaddr;			// host/IP translation
	
	newList = NULL;
	index = 0;
	size = sizeof(struct sockaddr_in6);
	if(getsockname(session->clientSocket, (struct sockaddr *)&bindAddr, &size) == 0){
		if(bindAddr.sin6_family == AF_INET6){
			IPv6 = TRUE;
			if(group = cJSON_GetObjectItem(relayCluster, "IP6"))
				index = cJSON_GetArraySize(group);
		}else{
			IPv6 = FALSE;
			if(group = cJSON_GetObjectItem(relayCluster, "IP4"))
				index = cJSON_GetArraySize(group);
		}
	}
	size = 0;
	if(index > 0){
		// allocate space for new list and populate
		if(newList = calloc(index+1, sizeof(struct clusterRecord))){
			rec = newList;
			prev = rec;
			copy = NULL;
			// try to populate list with host addresses corrisponding to URL strings in the list
			while(index-- && (item = cJSON_GetArrayItem(group, index))){
				rec = rec + 1;
				if(item->valuestring && strlen(item->valuestring)){
					if(copy)
						free(copy);
					copy = cJSON_strdup(item->valuestring);
					bzero(&rec->host, sizeof(struct sockaddr_in6));
					if(IPv6){
						if(host = strchr(copy, '[')){
							// If IPv6 address is bracket enclosed, must be a number
							host++;
							if((portstr = strchr(host, ']')) == NULL)
								continue;
							*portstr = 0;
							portstr++;
							if((portstr = strchr(portstr, ':')) == NULL)
								continue;
							portstr++;
						}else{
							// If IPv6 address is NOT bracket enclosed, must be a name
							host = copy;
							if((portstr = strchr(host, ':')) == NULL)
								continue;
							*portstr = 0;
							portstr++;
						}

						if((portno = atoi(portstr)) == 0)
							continue;						
						// First try the address as numeric format
						if((result = inet_pton(AF_INET6, host, &rec->host)) < 0)
							continue;						
						if(result == 0){
							// Otherwise, look up name
							hostaddr = gethostbyname2(host, AF_INET6);
							if(hostaddr == NULL)
								continue;
							// We have a resolved address!
							memcpy(&rec->host, hostaddr->h_addr_list[0], hostaddr->h_length);
						}
						rec->host.sin6_family = AF_INET6;
						rec->host.sin6_port = htons(portno);
#ifndef __linux__
						rec->host.sin6_len = sizeof(struct sockaddr_in6);
#endif						
						rec->hash = ELFHash(0, (char *)&rec->host, sizeof(struct sockaddr_in6));
						size++;
						prev->next = rec;
						prev = rec;
					}else{
						struct sockaddr_in *addr = (struct sockaddr_in *)&rec->host;
						host = copy;
						if((portstr = strchr(host, ':')) == NULL)
							continue;
						*portstr = 0;
						if((portno = atoi(portstr)) == 0)
							continue;						
						// First try the address as numeric format
						if((result = inet_pton(AF_INET, host, &addr->sin_addr)) < 0)
							continue;						
						if(result == 0){
							// Otherwise, look up name
							hostaddr = gethostbyname2(host, AF_INET);
							if(hostaddr == NULL)
								continue;
							// We have a resolved address!  Use first result
							memcpy(&addr->sin_addr.s_addr, hostaddr->h_addr_list[0], hostaddr->h_length);
						}
						addr->sin_family = AF_INET;
						addr->sin_port = htons(portno);
#ifndef __linux__
						addr->sin_len = sizeof(struct sockaddr_in);
#endif
						rec->hash = ELFHash(0, (char *)&rec->host, sizeof(struct sockaddr_in6));
						size++;
						prev->next = rec;
						prev = rec;
					}
				}
			}
			// string copy cleanup			   
			if(copy)
				free(copy);
			// mark end of list
			prev->next = NULL;
		}
	}
	if(newList && !size){
		// none of the hosts we allocated space for are valid... free the list.
		free(newList);
		newList = NULL;
	}	
		
	// send stop requests to items in old list and not in new
	removed = FALSE;
	if(old = session->clusterList){
		while(old = old->next){ 
			sendstop = TRUE;
			if(rec = newList){
				while(rec = rec->next){ 
					if(rec->hash == old->hash){
						if(rec->host.sin6_port == old->host.sin6_port){
							if(memcmp(&(rec->host), &(old->host), sizeof(struct sockaddr_in6)) == 0){
								// matching item in old and new list
								sendstop = FALSE;
								continue;
							}
						}
					}	
				}
			}
			if(sendstop){
				rspPacketRecvrRequestSend(session, &(old->host), FALSE);
				removed = TRUE;
			}
		}
	}
	if((session->relay_cluster == size) && !removed){
		// old and new lists are the same size and all the entries in the old list are also in
		// the new list.  The list has not changed!  Free the new list and keep the old list in place.
		free(newList);
		return;
	}
	
	// randomeize the list order -- only the first server in the cluster will forward reports
	// and be listed as "relay" for listener counting.  Randomize which cluster server this is
	// in the list for any given client, and which interleaver columns are served by a particular
	// cluster server.
	if((size > 1) && (rec = newList)){
		unsigned char movetofirst = (random() % size);
		uindex = 0;
		prev = rec;
		if(movetofirst){	
			// if movetofist is not already the first item
			while((uindex <= movetofirst) && (rec = rec->next)){
				if(uindex == movetofirst){
					// unhook current
					prev->next = rec->next;
					// move current to first
					rec->next = newList->next;
					newList->next = rec;
					break;
				}
				prev = rec;
				uindex++;
			}
		}
	}
	
	// free old list, set list-head to new list
	if(session->clusterList)
		free(session->clusterList);
	session->clusterList = newList;
	session->relay_cluster = size;

	// get cluster timeout value
	session->cluster_timeout = 0;
	if(item = cJSON_GetObjectItem(relayCluster, "Timeout"))
		session->cluster_timeout = item->valueint;
	
	if(session->cluster_timeout){
		// if cluster_timeout is non-zero, set all last heard times to now
		if(rec = session->clusterList){
			now = time(NULL);
			while(rec = rec->next)
				rec->lastHeard = now;
		}
	}
	
	// send 3 start requests (just incase two don't make it) to all items in new list, to get new relay 
	// index and count to the servers involved
	rspPacketRecvrRequestSend(session, NULL, TRUE);
	rspPacketRecvrRequestSend(session, NULL, TRUE);
	rspPacketRecvrRequestSend(session, NULL, TRUE);
}

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
unsigned char rspSessionSetPubKeyString(struct rspSession *session, char *key)
{
	BIO *bio;
	
	if(session->rsaPub)
		RSA_free(session->rsaPub);
	bio= BIO_new_mem_buf(key, -1);          
	session->rsaPub = PEM_read_bio_RSA_PUBKEY(bio, 0, 0, 0);    
	BIO_free(bio);	
	if(session->rsaPub)
		return RSP_ERROR_NONE;
	return RSP_ERROR_BADKEY;
}

unsigned char rspSessionSetPrivKeyFile(struct rspSession *session, FILE *fp, const char *passwd)
{
	if(session->rsaPriv)
		RSA_free(session->rsaPriv);
	// Initialize an RSA structure from that file
	session->rsaPriv = PEM_read_RSAPrivateKey(fp, 0, 0, (void *)passwd);
	if(session->rsaPriv == NULL)
		return RSP_ERROR_BADKEY;
	if(RSA_size(session->rsaPriv) != 272){	// rsp protocol requires 2176 bit key size... check for it.
		RSA_free(session->rsaPriv);
		session->rsaPriv = NULL;
		return RSP_ERROR_KEYSIZE;
	}
	return RSP_ERROR_NONE;
}
#endif
void rspSessionPresetReadPos(struct rspSession *session, unsigned char col, unsigned char block)
{
	// preset interelaver read position based on the current received packet address
	float pos, i;
	pos = (((float)col + modff((float)block / (float)session->interleaving, &i)) / 255.0) + i;
	resetReadPosition(session, pos);
	updateWriteLocation(session, calculateWriteLocation(session, col, block), TRUE);
}

unsigned char rspSessionFormatDiscover(struct rspSession *session, unsigned int size)
{
	// A new network packet is assumed to be in the session variable rsp_packet, of the specified size
	// and the session is assumed to be cleared for initialization or re-initialization.
	
	unsigned char byte_one;

	if(size < 19)
		return RSP_ERROR_SIZE;
	
	byte_one = session->rsp_packet[0];

	if((!session->ext_header[3] && !session->ext_header[4]) && ((byte_one & 0x03) == RSP_FLAG_PAYLOAD)){
		if(session->rsp_packet[2] != 0xff){
            // note interleaver position on first regular payload packet, that is not a reset packet
            // block address
            session->ext_header[3] = session->rsp_packet[1];
            // collumn address
            session->ext_header[4] = session->rsp_packet[2];
            return RSP_ERROR_WAITING;
        }
	}
	
	if((byte_one & 0x03) == RSP_FLAG_EXT){
		// we received an extended packet!!
		unsigned char fec;
		unsigned char il;

		fec = session->rsp_packet[1];
		il = session->rsp_packet[2] & 0x3f;	// lower seven bits only

		if(!session->ext_header[0] && !session->ext_header[1] && !session->ext_header[2]){
			// first one received... save it so we can validate it against another
			session->ext_header[0] = byte_one;
			session->ext_header[1] = fec;
			session->ext_header[2] = il;
		}else if((session->ext_header[0] != byte_one) && (session->ext_header[1] != fec) && (session->ext_header[2] != il)){
			// Doesn't match first one received... save it now as the first one...
			session->ext_header[0] = byte_one;
			session->ext_header[1] = fec;
			session->ext_header[2] = il;
		}else if(session->ext_header[3] || session->ext_header[4]){
			// previous and curret match: now we know the size, flags, FEC settings and interleaver settings...
			// and we have a last write position too...
			unsigned char payload_size;
			payload_size = byte_one & 0xF0;
			payload_size = payload_size + 16;
			
			session->FECroots = fec;
			session->interleaving = il;
			session->colSize = payload_size;
			session->flags = byte_one & 0x0C;
			
			
			unsigned char rsp_err;
			if((rsp_err = rspSessionInit(session)) != RSP_ERROR_NONE)
				rspSessionClear(session, FALSE);
			else
				// preset interelaver read position based on the current received packet address
				rspSessionPresetReadPos(session, session->ext_header[4], session->ext_header[3]);
			return rsp_err;
		}
	}
	return RSP_ERROR_WAITING;
}

unsigned char rspSessionWritePacket(struct rspSession *session, unsigned int *size, struct timespec *lastTime)
{
	unsigned char flags;
	unsigned char block, lb;
	unsigned char col;
	unsigned short payload_size;
	unsigned char rsp_err;
	float pos, bk_diff, row_diff;
	
	// The following function gets basic info from a received packet and performs RS decoding, Decrypting, and/or CRC checking on the packet.
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	rsp_err = rspPacketReadHeader(session->rsp_packet, *size, &flags, &payload_size, &col, &block, session->network_rs, session->rsaPub, session->crc_table);
#else
	rsp_err = rspPacketReadHeader(session->rsp_packet, *size, &flags, &payload_size, &col, &block, session->network_rs, NULL, session->crc_table);
#endif    
	*size = payload_size;
	if((flags & 0x03) == RSP_FLAG_RR)
		return RSP_ERROR_RRPCKT;
	
	// Avr time constant = 0.1 buffer
	// apply per-packet time constant to statistics
	session->DupStat = session->DupStat * (1.0 - session->columnScaling);
	session->BadStat = session->BadStat * (1.0 - session->columnScaling);

	if(session->debugSock > -1){
		// print packet receprion report to the specified socket
		char buf[128], ipStr[49], *type;
		int size;
		strcpy(ipStr, "unknown sender");
		if(session->lastAddr.sin6_family == AF_INET){
			struct sockaddr_in *addr = (struct sockaddr_in *)&session->lastAddr;
			inet_ntop(session->lastAddr.sin6_family, &(addr->sin_addr), ipStr, sizeof(ipStr));
		}
		else if(session->lastAddr.sin6_family == AF_INET6){
			inet_ntop(session->lastAddr.sin6_family, &session->lastAddr.sin6_addr, ipStr, sizeof(ipStr));
		}
		if((flags & 0x03) == RSP_FLAG_AUTH)
			type = "authent";
		else if((flags & 0x03) == RSP_FLAG_EXT)
			type = "extended";
		else
			type = "payload";
		size = snprintf(buf, sizeof buf, "From %s Port %d > err=%d type=%s col=%d blk=%d\n", ipStr, 
						htons(session->lastAddr.sin6_port), rsp_err, type, col, block);
		if(write(session->debugSock, buf, size) < 0){
			close(session->debugSock);
			session->debugSock = -1;
		}
	}
	
	if(rsp_err == RSP_ERROR_NONE){
		if((flags & 0x03) == RSP_FLAG_AUTH){
			lb = block / session->interleaving;
			bk_diff = session->rdPosition + kTargetWrRdGap - 0.5;
			if(bk_diff > 3)
				bk_diff = bk_diff - 3;
			if(lb != (unsigned char)bk_diff){
				bk_diff = session->rdPosition + kTargetWrRdGap + 0.5;
				if(bk_diff > 3)
					bk_diff = bk_diff - 3;
				if(lb != (unsigned char)bk_diff){
					// Not for a logical block within +/- 0.5 logical blocks of the target write time.
					// target write location is the current read location + target read/write gap (kTargetWrRdGap).
					// Early or late beyond the acceptable window: Don't use this packet 
					session->BadStat = session->BadStat + session->columnScaling;
					return RSP_ERROR_WINDOW;
				}
			}
			
			if(il_getChecksumValid(session->interleaver, block))
				// If we already received this auth packet:  Set the DUP error flag, but continue process the packet anyway.
				// We need to set the flag to prevent relay of this packet, preventing a packet loop for cross-fed servers.
				rsp_err = RSP_ERROR_DUP;
			
			// NOTE: Process checksum even if one has already been received for this column, to prevent a "dead-lock" situation
			// that could otherwise occur if a network feed is broken long enough for the block numbers to roll-over.  In this case
			// the checksums already stored are old and will cause the rejection of data packets.  By allowing checksum overwites,
			// we allow the "newer" checksums to replace the old ones from the roll-over event which RSP would otherwise not detect.

			// handle auth packet
			il_receiverChecksums(session->interleaver, block, session->rsp_packet + 2);
			return rsp_err;
		}
		
		// check if format flags match our configurartion
		if(session->colSize != payload_size){
			rsp_err = RSP_ERROR_FORMAT;
			goto fail;
		}
		if(col == 0xFF){
			// handle reset packet
			// check authentication if any
			/*			if(session->rsaPub){
			 unsigned char byte;
			 
			 if(RSA_public_decrypt(17, session->rsp_packet + 1, &byte, session->rsaPub, RSA_PKCS1_PADDING) != 1)
			 return RSP_ERROR_RSA;
			 if(byte != block)
			 return RSP_ERROR_RSA;
			 }
			 */
			rspSessionClear(session, FALSE);
			return RSP_ERROR_RESET;
		}
        
		if(block >= (session->interleaver->ratio * 3)){
			rsp_err = RSP_ERROR_FORMAT;
			goto fail;
		}
		// verify checksum if checksums are available
		if(il_getChecksumValid(session->interleaver, block)){
			if((flags & 0x03) == RSP_FLAG_EXT){
				if(il_getChecksum(session->interleaver, col, block) != checkSum(session->rsp_packet + 5, payload_size)){
					rsp_err = RSP_ERROR_AUTH;
					goto fail;
				}
			}else{
				if(il_getChecksum(session->interleaver, col, block) != checkSum(session->rsp_packet + 3, payload_size)){
					rsp_err = RSP_ERROR_AUTH;
					goto fail;
				}
			}
		}
		// write data to the interlever at the packet's specified column and block location
		if((flags & 0x03) == RSP_FLAG_EXT){
			// verify extended packet format info still matches the session
			if((session->FECroots != session->rsp_packet[1]) || (session->interleaving != session->rsp_packet[2])){
				rsp_err = RSP_ERROR_FORMAT;
				goto fail;
			}			
			rsp_err = il_writeColumn(session->interleaver, session->rsp_packet + 5, col, block, 0);
		}else
			rsp_err = il_writeColumn(session->interleaver, session->rsp_packet + 3, col, block, 0);
		
		// note last-heard for cluster list entry timeout, even if this is a dup packet
		if(session->relay_cluster && session->cluster_timeout){
			unsigned int hash;
			struct clusterRecord *rec;
			hash = ELFHash(0, (char *)&session->lastAddr, sizeof(struct sockaddr_in6));
			rec = session->clusterList;
			while(rec = rec->next){
				if(rec->hash == hash){
					// hash matches, check for port number matches and then a full memory compare...
					if(rec->host.sin6_port == session->lastAddr.sin6_port){
						if(memcmp(&(rec->host), &(session->lastAddr), sizeof(struct sockaddr_in6)) == 0){
							// a match! Update lastheard time
							rec->lastHeard = time(NULL);
							break;
						}
					}
				}
			}
			
		}	
		
		if(rsp_err == 0){
			// increment dup packet statistic
			session->DupStat = session->DupStat + session->columnScaling;
			if(session->DupStat > 0.9){	// roll over problem... re-sync interleaver
				il_reset(session->interleaver);
				session->avWrPosition = 0.0;
				session->lastWrPos = 0.0;
				session->rdPosition = 0.0;
				session->wrRate = -1.0;
				session->DupStat = 0.0;
				// preset interelaver read position based on the current received packet address
				rspSessionPresetReadPos(session, col, block);
			}
			
			return RSP_ERROR_DUP;
		}
        
		// use only normal payload packets for timming!  They could be pre-roll extended packets auth authentication packets.
		if((flags & 0x03) == RSP_FLAG_PAYLOAD){
			pos = calculateWriteLocation(session, col, block);
			
			// Make sure current position is after average position before using it for timing and averaging 
			if(pos >= session->avWrPosition){
				updateWriteLocation(session, pos, FALSE);
				
				// Check for early or late packets
				bk_diff = rspSessionGetReadOffsetFromWritePos(session, pos) - kTargetWrRdGap;				
				if(bk_diff > 0.5 || bk_diff < -0.5){
					// Early or late beyond the acceptable window: Don't use this packet for timing.... 
					session->BadStat = session->BadStat + session->columnScaling;
					return RSP_ERROR_NONE;
				}
				bk_diff = session->lastWrPos;
				if(!lastTime)
					session->lastWrPos = pos;
				else{
					// Update write pace statistics
					struct timespec now;
					clock_gettime(CLOCK_MONOTONIC, &now);

					if(session->wrRate < 0.0){
						// reset lastTime to now
						*lastTime = now;
						session->lastWrPos = pos;
						session->wrRate = 0.0;
						return RSP_ERROR_NONE;
					}
					
					if(lastTime->tv_sec || lastTime->tv_nsec){
						// get interleaver position difference in blocks after the last write
						bk_diff = pos - bk_diff;
						float period = (float)(now.tv_sec - lastTime->tv_sec);
						period = period + (float)(now.tv_nsec - lastTime->tv_nsec) * 1.0e-9;
						// convert from blocks to rows
						row_diff = bk_diff * (float)session->interleaving * (float)session->colSize;
						if((period > 1.0e-3) && (bk_diff > 0.0)){ 
							// Period, etc. are above lower limit: Save the curent time and position and 
							// check for further processing.  Otherwise we skip until next time, keeping 
							// the last time and position values unchanged.
							session->lastWrPos = pos;
							*lastTime = now;
							// calculate upper limit: 1 logical block time based on current average rate.
							float upperLimit = session->wrRate * session->interleaver->rows * session->interleaver->ratio;
							if(upperLimit == 0.0)
								upperLimit = 10.0;
							if(upperLimit > 100.0)	// reasonable cap
								upperLimit = 100.0;
							if((period < upperLimit) && (bk_diff < 1.0)){
								// Period, etc. are all within upper limits and positive, use this 
								// information to update the average rate.  Otherwise skip this step and 
								// hope for better data next time.
								float rate = period / row_diff;
								if((session->wrRate <= 0.0) && (rate > 0.0)){
									session->wrRate = rate;
									// bw is a avreraging filter bandwidth multiplier used to start
									// averaging out fast, then slow it down as new data comes in
									session->bw = 100.0;
								}else{
									// slowly move the bandwidth toward 0.1, logical blocks. 
									session->bw = session->bw + ((0.1 - session->bw) * session->columnScaling);
									if((bk_diff = bk_diff * session->bw) > 1.0)
										bk_diff = 1.0;
									// Lowpass (averaging) IIR filter.
									session->wrRate = session->wrRate + ((rate - session->wrRate) * bk_diff);
								}
							}
						}
					}else{
						// lastTime has not yet been initialized... do it now. 
						session->lastWrPos = pos;
						*lastTime = now;
					}
				}
			}
		}
		
		if(session->reportToSource)
			// update report address to the address from which the last valid packet was received from
			memcpy(&session->rrAddr, &session->lastAddr, sizeof(struct sockaddr_in6));
		
		return RSP_ERROR_NONE;
	}
	
fail:
	// increment bad packet statistic
	session->BadStat = session->BadStat + session->columnScaling;
	return rsp_err;
	
	// note: on return *size has been updated from the packet size value on entry to the payload size
}

unsigned int rspSessionReadPacket(struct rspSession *session, unsigned char **packet, unsigned char *data)
{
	unsigned char tempBuff[session->interleaver->rows];
	unsigned char *cs;
	unsigned char block;
	unsigned char i;
	unsigned short size;
	int lb_size;
	
	if(!data)
		data = tempBuff;
	lb_size = session->interleaver->columns * session->interleaver->rows * session->interleaver->ratio;
	// check for interleaver output
	if((il_rowColumnOverlap(session->interleaver) == 0) && (session->interleaver->rwBalance > lb_size)){
		// current rows (write) and colums (read) locations are not overlapped... 
		// and we have writen more bytes then we have read from the interleaver...
		// send some data from the interleaver
		if((session->interleaver->colIdx == 0) && il_getChecksumValid(session->interleaver, session->interleaver->colBlock)){
			// start of new block (column = 0)  Send checksums if available.  
			// and send encrypted checksum packet
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
			size = rspPacketSignedChecksumsSet(session->rsp_checksum_packet, il_getChecksums(session->interleaver, session->interleaver->colBlock), session->interleaver->colBlock, session->rsaPriv, session->crc_table);
#else
            size = 0;
#endif
			*packet = session->rsp_checksum_packet;
			// done with checksums... mark as invalid so we don't send again.
			cs = il_getChecksums(session->interleaver, session->interleaver->colBlock);
			cs[session->interleaver->columns] = 0;
			return size;
		}
		il_copyCurColumn(session->interleaver, data);
		session->interleaver->rwBalance = session->interleaver->rwBalance -	session->interleaver->rows;	// bytes read from interleaver
		if(session->extCount++ >= 200){
			// send reset packet
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
			size = rspPacketResetSet(session->rsp_packet, session->network_rs, session->rsaPriv, session->crc_table);
#else
            size = rspPacketResetSet(session->rsp_packet, session->network_rs, NULL, session->crc_table);
#endif
		}else if(session->extCount++ >= 100){
			// make every one in 100 payload packets an extended payload packet... 
			size = rspPacketPayloadSet(session->rsp_packet, data, session->network_rs, session->interleaver->colIdx, session->interleaver->colBlock, session->FECroots, session->interleaving, session->crc_table);
			// reset extended payload counter
			session->extCount = 0;
		}else
			size = rspPacketPayloadSet(session->rsp_packet, data, session->network_rs, session->interleaver->colIdx, session->interleaver->colBlock, 0, 0, session->crc_table);
		block = session->interleaver->colBlock;	// note the block we are currently in
		if(il_nextColumn(session->interleaver)){
			// crossed a logical block bundry... clear the old blocks
			block = (block / session->interleaver->ratio) * session->interleaver->ratio;
			for(i=0; i<session->interleaver->ratio; i++)
				il_clearBlock(session->interleaver, block + i);
		}
		*packet = session->rsp_packet;
		return size;
	}
	return 0;
}

unsigned char rspSessionWriteData(struct rspSession *session, unsigned char *data, unsigned int size)
{
	unsigned char block;
	unsigned char *ptr;
	unsigned int i;

	// check size
	if(size != (255 - session->FECroots))
		return RSP_ERROR_SIZE;
	
	// encode... writing to current interleaver row
	ptr = il_getCurRow(session->interleaver);
	// copy existing data
	memcpy(ptr, data, size);
	// append check codes
	encode_rs_char(session->audio_rs, data, ptr+size);
	
	session->interleaver->rwBalance = session->interleaver->rwBalance + 255;
	
	block = session->interleaver->rowBlock;	// note the block we are currently in
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	if(il_nextRow(session->interleaver) && session->rsaPriv){
		// crossed block boundry... calculate authentication checksums
		block = block - (block % session->interleaver->ratio);
		for(i=0; i<session->interleaver->ratio; i++)
			il_updateBlockChecksums(session->interleaver, block + i);
	}
#endif
	return RSP_ERROR_NONE;
}

unsigned char *rspSessionPacedReadData(struct rspSession *session, unsigned int *size, struct timespec *lastTime)
{
	struct timespec now;
	float period;
	float i;
	unsigned char *result;
	
	// returns NULL if nothing more to read
	// returns data pointer with size = 0 if there was an error (broken stream continunity)
	// returns data pointer and corrisponding size if all is well
	
	*size = 0;
	result = NULL;
	if(session->wrRate > 0.0){
		clock_gettime(CLOCK_MONOTONIC, &now);
		if((lastTime->tv_sec || lastTime->tv_nsec) && (session->wrRate > 0.0)){
			period = (float)(now.tv_sec - lastTime->tv_sec);
			period = period + (float)(now.tv_nsec - lastTime->tv_nsec) * 1.0e-9;
			
			if(period < 1.0e-6)
				period = 1.0e-6;
			if((result = rspSessionReadData(session, size, &period, FALSE)) == NULL){
				if(period < 0){
					// return a pointer with period < 0 indicate break in stream, played to buffer end
					// and reset wrRate statistics and clear interleavers to re-sync with source
					*size = 0;
					result = il_getCurRow(session->interleaver);
					if(session->playing){
						// and reset pace stats
						session->wrRate = -1.0;
						session->playing = FALSE;
						// clear all blocks and start over on syncronization
						il_reset(session->interleaver);	
						session->avWrPosition = 0.0;
						session->lastWrPos = 0.0;
						session->rdPosition = 0.0;
						session->wrRate = -1.0;
					}
				}
				return result;
			}
			if(!session->playing && *size)
				session->playing = TRUE;
			
			lastTime->tv_nsec = lastTime->tv_nsec + modff(period, &i) * 1.0e9;
			while(lastTime->tv_nsec > 1.0e9){
				lastTime->tv_nsec = lastTime->tv_nsec - 1.0e9;
				i++;
			}
			lastTime->tv_sec = lastTime->tv_sec + (int)i;
			
		}else{
			*lastTime = now;
		}
	}
	return result;
}

unsigned char *rspSessionReadData(struct rspSession *session, unsigned int *size, float *period, unsigned char beyond)
{
	unsigned char *data;
	unsigned char i;
	unsigned char block;
	int corrections;
	float bal_err, target;
	unsigned short eCount;
	unsigned char erasures[255];
	
	// return NULL if nothing to read
	// returns data pointer with size = 0 for error
	// returns data pointer and data size if all is well
	
	// balance read/write rate:read kTargetWrRdGap logical blocks behind the average write point.
	// averaging introduces an additional 0.1 block delay	
    
    if((bal_err = rspSessionGetBalance(session)) > 0.5){
		// Writing is too far ahead... skip reading ahead to prevent new data overwriting
		resetReadPosition(session, session->avWrPosition);
		// and return size = 0 with data pointer inidcating a break in the stream
		*size = 0;
		return il_getCurRow(session->interleaver);		
	}
	if(period){
		if(bal_err < -1){
			// reached the end of the buffer
			*period = -1;
			*size = 0;
			return 0;
		}		
		if(bal_err > 0){
			target = session->wrRate * 0.9;	// set target 10% faster than write rate
//fprintf(stderr, "bal=%f, f: tar=%f\n", bal_err, session->wrRate);

		}else{
			target = session->wrRate * 1.1;	// set target 10% slower than write rate
//fprintf(stderr, "bal=%f, s: tar=%f\n", bal_err, session->wrRate);
		}
        if(*period < target){
			// nothing to read right now
			*period = 0;
			*size = 0;
			return 0;
		}
		*period = target;
	}else if((bal_err < -1) || (!beyond && (bal_err < 0))){
		// nothing to read
		*size = 0;
		return 0;		
	}

	// apply per-frame time constant to statistics 
	session->FECStat = session->FECStat * (1.0 - session->rowScaling);
	session->ErrStat = session->ErrStat * (1.0 - session->rowScaling);
	
	data = il_getCurRow(session->interleaver);		
	// rs decode raw interleaver row
	eCount = il_getBlockErasures(session->interleaver, session->interleaver->rowBlock, erasures);		
	if(eCount > session->FECroots){
		session->ErrStat = session->ErrStat + session->rowScaling;
		session->FECStat = session->FECStat + (session->rowScaling * eCount);
		corrections = -1;
	}else{		
		corrections = decode_rs_char(session->audio_rs, data, erasures, eCount);
		if(corrections < 0){
			session->ErrStat = session->ErrStat + session->rowScaling;
			session->FECStat = session->FECStat + (session->rowScaling * session->FECroots);
		}else{
			session->FECStat = session->FECStat + (session->rowScaling * corrections);
			
			// get meta byte, if any (first byte)
			if(*data){
				// non-zero meta byte... add to string, aloocating string space if needed
				appendchr(&session->metaString, *data);
			}else{
				if(session->metaString){
					// end of string reached.... process the meta data
					if(!session->metaCorrupt){
						cJSON *metaData;
						if(metaData = cJSON_Parse(session->metaString))
							rspSessionQueueMetadata(session, metaData, NULL);
					}
					free(session->metaString);
					session->metaString = NULL;
				} 
				session->metaCorrupt = FALSE;
			}
		}
	}
	if((corrections < 0) && (session->metaString))
		session->metaCorrupt = TRUE;
	// move data frame pointer past meta data byte
	data = data + 1;
	
//if(debugSession == session)
//	fprintf(stdout, "read: 	blk= %i, col=%i\n", session->interleaver->rowBlock, session->interleaver->rowIdx);
	
	if((session->interleaver->rowIdx == (session->interleaver->rows - 1)) && ((session->interleaver->rowBlock % session->interleaver->ratio) == (session->interleaver->ratio - 1))){
		// we just finished reading a logical block, clear the block
		block = session->interleaver->ratio * (session->interleaver->rowBlock / session->interleaver->ratio);
		for(i=0; i<session->interleaver->ratio; i++){
			il_clearBlock(session->interleaver, block + i);	
//if(debugSession == session)
//	fprintf(stdout, "clear: blk= %i\n", block + i);

		}
	}
	il_nextRow(session->interleaver);
	updateReadLocation(session, session->interleaver->rowIdx, session->interleaver->rowBlock, FALSE);
	if(corrections < 0)
		// we could not correct this frame... do not process it.
		*size = 0;
	else
		*size = session->interleaver->columns - session->FECroots - 1;
	return data;
}

float calculateWriteLocation(struct rspSession *session, unsigned char col, unsigned char block)
{
	float pos, i;
	
	pos = (((float)col + modff((float)block / (float)session->interleaving, &i)) / 255.0) + i;
	if(pos < session->rdPosition)
		pos = pos + 3.0;
	return pos;
}

void updateWriteLocation(struct rspSession *session, float pos, unsigned char reset)
{
	// IIR avareging filter applied if reset is FALSE: introduced 0.1 buffer delay
	if(reset)
		session->avWrPosition = pos;
	else
		session->avWrPosition = session->avWrPosition + (pos - session->avWrPosition) * session->columnScaling;
}

void updateReadLocation(struct rspSession *session, unsigned char row, unsigned char block, unsigned char reset)
{
	// Unless reset is true, read is assumed to always move forward
	float was = session->rdPosition;
	session->rdPosition = ((float)block + ((float)row / (float)session->colSize)) / (float)session->interleaving;
	if(!reset && (session->rdPosition < was)){
		// block rollover
		session->avWrPosition = session->avWrPosition - 3.0;
		session->lastWrPos = session->lastWrPos - 3.0;
	}
}

void resetReadPosition(struct rspSession *session, float writePos)
{
	float i, rdPos;
	unsigned char rd_block;
	
	rdPos = writePos - kTargetWrRdGap;
	if(rdPos < 0)
		rdPos = rdPos + 3;
	rdPos = modff(rdPos, &i) * (float)session->interleaving;
	rd_block = (unsigned char)(i * session->interleaving);
	session->interleaver->rowIdx = (unsigned char)(modff(rdPos , &i) * (float)session->colSize);
	session->interleaver->rowBlock = rd_block +  (unsigned char)i;
	updateReadLocation(session, session->interleaver->rowIdx, session->interleaver->rowBlock, TRUE);	
}

float rspSessionGetReadOffsetFromWritePos(struct rspSession *session, float wrPos)
{	
	return fmodf(wrPos, 6.0) - session->rdPosition;
}

float rspSessionGetBalance(struct rspSession *session)
{
	// read/write balance in blocks: - for read ahead of write, + for read behind write 
	// where target point is reading kTargetWrRdGap	blocks behind the average write position
	// averaging introduces an additional 0.1 block delay
	return rspSessionGetReadOffsetFromWritePos(session, session->avWrPosition) - (kTargetWrRdGap - 0.1);
//	return (fmodf(session->avWrPosition, 6.0) - (kTargetWrRdGap - 0.1)) - session->rdPosition;
}

void rspSessionQueueMetadata(struct rspSession *session, cJSON *meta, cJSON *excludeList)
{	
	cJSON **metaHandle;
	cJSON *metaID, *this, *obj;
	unsigned int mID;
	char *tag;
	
	pthread_mutex_lock(&session->metaMutex);
	while(this = cJSON_DetachItemFromArray(meta, 0)){
		if(this->string && strlen(this->string)){
			tag = cJSON_strdup(this->string);
			if(excludeList){
				cJSON *e = excludeList->child;
				while(e){
					if(e->valuestring && (strcmp(tag, e->valuestring) == 0)){
						// this items tag matches a string in the exclude list, skip it!
						cJSON_Delete(this);
						free(tag);
						break;
					}
					e = e->next;
				}
				if(e)
					continue;
				// if we get here, then the tag string doesn't match any of the string items in the exclude list.				
			}
			mID = 0;
			// check if this is a repeat item (non-zero mID) then check make sure we don't already have it in the repeat record
			if(metaID = cJSON_GetObjectItem(this, "mID"))
				mID = metaID->valueint;
			if(mID){
				if(obj = cJSON_GetObjectItem(session->metaRepeat, tag)){
					// we have a repeate record for this... see if the mID has changed
					if(metaID = cJSON_GetObjectItem(obj, "mID")){
						if(metaID->valueint != mID)
							// new item mID... update
							cJSON_ReplaceItemInObject(session->metaRepeat, tag, this);
						else{
							// we already have this... just ignore it
							free(tag);
							cJSON_Delete(this);
							continue;
						}
					}
				}else{
					// no repeate item for this yet... add it
					cJSON_AddItemToObject(session->metaRepeat, tag, this);
				}

				// create a copy of the item to put in the normal meta queue as well
				char *metaStr = cJSON_PrintUnformatted(this);
				if(metaStr == NULL){
					free(tag);
					continue;
				}
				this = cJSON_Parse(metaStr);
				free(metaStr);
				if(this == NULL){
					free(tag);
					continue;
				}
				this->string = cJSON_strdup(tag);
			}
			// go ahead and add this non-repeat, or new/updated repeate item to the meta queue
			if(obj = cJSON_CreateObject()){
				// create a holding object then add this item to the holder
				cJSON_AddItemToObject(obj, tag, this);
				// then queue the holder
				session->metaQueue[session->wrQueIdx & 0x0F] = obj;
				session->wrQueIdx = (session->wrQueIdx + 1) & 0x0F;
				if(session->rdQueIdx == session->wrQueIdx){
					// overlap... drop oldest read record
					metaHandle = &session->metaQueue[session->wrQueIdx & 0x0F];
					if(*metaHandle){
						cJSON_Delete(*metaHandle);
						*metaHandle = NULL;
					}
					session->rdQueIdx = (session->rdQueIdx + 1) & 0x0F;
				}
			}else
				cJSON_Delete(this);
			free(tag);
		}
	}
	cJSON_Delete(meta);
	pthread_mutex_unlock(&session->metaMutex);	
}

cJSON *rspSessionNextMetadata(struct rspSession *session)
{
	cJSON **metaHandle;
	cJSON *metaPtr;
	
	pthread_mutex_lock(&session->metaMutex);
	if(session->rdQueIdx == session->wrQueIdx){
		pthread_mutex_unlock(&session->metaMutex);
		return NULL;
	}
	
	metaHandle = &session->metaQueue[session->rdQueIdx & 0x0F];
	metaPtr = *metaHandle;
	*metaHandle = NULL;
	session->rdQueIdx = (session->rdQueIdx + 1) & 0x0F;
	pthread_mutex_unlock(&session->metaMutex);
	return metaPtr;
}

void rspSessionExpiredMetaCheck(struct rspSession *session)
{
	cJSON *metaPtr, *obj;
	unsigned long timeDiff;
	int index;
	time_t now;
	
	// check remaining time on liftime limited items. 
	now = time(NULL);
	if(session->lastMetaTime == 0)
		timeDiff = 0;
	else
		timeDiff = now - session->lastMetaTime;
	session->lastMetaTime = now;
	if(timeDiff > 0){
		pthread_mutex_lock(&session->metaMutex);
		obj = session->metaRepeat->child;  
		index = 0;
		while(obj){
			if(metaPtr = cJSON_GetObjectItem(obj, "lifetime")){
				metaPtr->valueint = metaPtr->valueint - timeDiff;
				if(metaPtr->valueint <= 0){
					obj = obj->next;
					// lifetime over... remove from object from repeate list
					cJSON_DeleteItemFromArray(session->metaRepeat, index);
					continue;
				}
			}
			obj = obj->next;
			index++;
		}
		pthread_mutex_unlock(&session->metaMutex);
	}
}

char *rspSessionNextMetaStr(struct rspSession *session)
{
	char *metaStr;
	cJSON *metaPtr, *obj;
	
	// caller must free returned string if not NULL
	metaStr = NULL;
	if(metaPtr = rspSessionNextMetadata(session)){
		// new meta data to send
		metaStr = cJSON_PrintUnformatted(metaPtr);
		cJSON_Delete(metaPtr);
	}else{	
		// check to remove expired repeate metadata
		rspSessionExpiredMetaCheck(session);
		pthread_mutex_lock(&session->metaMutex);
		if(metaPtr = cJSON_GetArrayItem(session->metaRepeat, session->repeateIndex)){
			session->repeateIndex++;
		}else{
			session->repeateIndex = 0;
			if(metaPtr = cJSON_GetArrayItem(session->metaRepeat, session->repeateIndex))
				session->repeateIndex++;
		}
		if(metaPtr){
			if(obj = cJSON_CreateObject()){
				// create a holding object then add this item to the holder
				cJSON_AddItemReferenceToObject(obj, metaPtr->string, metaPtr);
				metaStr = cJSON_PrintUnformatted(obj);
				cJSON_Delete(obj);
			}
		}
		pthread_mutex_unlock(&session->metaMutex);
	}
	return metaStr;
}

void rspSessionCheckStatusTime(struct rspSession *session)
{
	unsigned int usize;
	unsigned char count;
	struct clusterRecord *rec;

	// check if it's past time to send a receiver report
	if(session->rrPeriod && (time(NULL) > (session->lastReport + session->rrPeriod))){
		// send reciever report
		
		// handle cluster	
		if(session->relay_cluster && session->relay && (rec = session->clusterList)){
			// check for timeouts
			if(session->cluster_timeout){
				count = 0;
				while((rec = rec->next)){
					if(time(NULL) > (rec->lastHeard + session->cluster_timeout))
						// timeout: suspend definitive of this server from the cluster, but keep trying to use it
						rec->suspend = 1;
					else{
						rec->suspend = 0;
						count++;
					}
				}
				// reset linked list back to start
				rec = session->clusterList;
				// set the new count: number of cluster entries that are NOT suspended at this time
				if(count < 1)
					// at a minimum we must have a cluster count of 1, so atleast all the entries keep trying
					count = 1;
				session->relay_cluster = count;
			}
			// send reports for servers in the list
			session->relay = 1;
			while((rec = rec->next) && (usize = rspPacketRecvrReportSet(session, FALSE))){
				rspSendto(session->clientSocket, session->rsp_checksum_packet, usize, 0, (struct sockaddr*)&rec->host);
				if(!rec->suspend && (session->relay < session->relay_cluster))
					session->relay++;
			}
			session->relay = 1;
		}else{
			if((session->rrAddr.sin6_port) && (usize = rspPacketRecvrReportSet(session, FALSE)))
				rspSendto(session->clientSocket, session->rsp_checksum_packet, usize, 0, (struct sockaddr*)&session->rrAddr);
			if((session->rrAddr2.sin6_port) && (usize = rspPacketRecvrReportSet(session, TRUE)))
				// send to secondary server as well (for redundent stream)
				rspSendto(session->clientSocket, session->rsp_checksum_packet, usize, 0, (struct sockaddr*)&session->rrAddr2);
		}
		session->lastReport = time(NULL);
	}	
}

int rspSessionNetworkRead(struct rspSession *session, unsigned char noBlock)
{
	int size;
	unsigned int usize;
	unsigned int err_no;
	usize = sizeof(struct sockaddr_in6);
	if(noBlock)
		size = recvfrom(session->clientSocket, session->rsp_packet, sizeof(session->rsp_packet), MSG_DONTWAIT, (struct sockaddr *)&session->lastAddr, &usize);	
	else
		size = recvfrom(session->clientSocket, session->rsp_packet, sizeof(session->rsp_packet), 0, (struct sockaddr *)&session->lastAddr, &usize);	
	if(size < 0){
		// get socket error number
		usize = sizeof(err_no);
		getsockopt(session->clientSocket, SOL_SOCKET, SO_ERROR, &err_no, &usize);
		if((err_no == 0) || (err_no == EAGAIN)){
			// socket timed out... just set size to zero so we know that there is no packet
			size = 0;
		}else
			return -1;
	}
	rspSessionCheckStatusTime(session);
	return size;
}

unsigned char rspSessionFillTask(struct rspSession *session, char** msg, struct timespec *lastRxTime)
{
	int result;
	unsigned int usize;
	unsigned char rsp_err;
	
	// This function needs to be called repreatedly to process received network data and keep the interleaver full.
	// This is already handled by the rspSessionPlayTaskPush function if the "push" methode of playback is used.
	// If you use the "pull" playback methode with the rspSessionPlayTaskPull function, then you will need to 
	// call this function directly - See rspSessionPlayTaskPull task comments for details.	
	
	// *msg will be set on return if there is a server message (like server full) to process.
	// If *msg string is set on return, the caller is responsable for freeing it.
	
	rsp_err = RSP_ERROR_NONE;
	*msg = NULL;
	
	result = rspSessionNetworkRead(session, 0);

	if(result > 0){	
		usize = result;
		if(session->interleaver == NULL){
			// Waiting to discover rsp format (via reception of extended payload packet)
			pthread_mutex_lock(&session->threadLock); 
			rsp_err = rspSessionFormatDiscover(session, usize);
			pthread_mutex_unlock(&session->threadLock); 
		}else{
			// We have new data... 
			pthread_mutex_lock(&session->threadLock); 
			rsp_err = rspSessionWritePacket(session, &usize, lastRxTime);
			pthread_mutex_unlock(&session->threadLock); 
			if(rsp_err == RSP_ERROR_RRPCKT){
				// handle message from relay server, such as "server full"
				// Message string length in size variable
				// jSON formated message string is at session->rsp_packet + 1
				if(msg){
					// just to be safe, make sure the last byte is a NULL so we can handle the data as a string
					*(session->rsp_packet + 1 + usize) = 0;
					// caller is responsable for freeing msg string.
					*msg = malloc(strlen((char *)session->rsp_packet+1) + 1);
					strcpy(*msg, (char *)session->rsp_packet+1);
				}
			}				
		}
	}else if(result < 0){
		// network error
		return RSP_ERROR_NETWORK;	
	}
	return rsp_err;
}


unsigned char *rspSessionPlayTaskPull(struct rspSession *session, cJSON **meta, int *size, unsigned char beyond)
{
	unsigned int usize;
	unsigned char *data;
	cJSON *item;

	// This is a "Pull Mode" playtask: It is non-blocking and expects to be called when the caller is ready for more stream data.
	// On average, the caller must "pull" new stream data from this function at the same rate which it is being streamed to prevent
	// the interleaver from running dry or over-flowing. 
	// Since this function only handles reading stream data, and is assumed to be called only when needed, the rspSessionFillTask 
	// function must be called repeatedly and simultaneously in a separate thread to keep the interleaver filled with new network
	// Separate threading is required because network packets will surely arrive even when the client is not ready for more stream data. 
	// ONLY This function and rspSessionFillTask are thread-safe with respect to each other.  All other rsp functions assume any rspSession 
	// instance is being accessed by one thread at a time.
	
	// return NULL if nothing available to read yet.
	// returns data pointer with size = 0 for error (broken stream continunity)
	// returns data pointer and data size if all is well
	
	// The *meta pointer will be set on return if there is new meta data process.
	
	*size = 0;
	*meta = NULL;
	data = NULL;

	
	pthread_mutex_lock(&session->threadLock); 
	data = rspSessionReadData(session, &usize, NULL, beyond);
	pthread_mutex_unlock(&session->threadLock); 
	
	if(data){
		if(usize){
			// check for new meta data
			if(*meta = rspSessionNextMetadata(session)){
				if(session->relay && (item = cJSON_GetObjectItem(*meta, "Cluster")))
					//new cluster list metadata	
					rspSessionClusterSetup(session, item);
			}
			if(!session->playing)
				session->playing = TRUE;
		}else if(session->playing)
			session->playing = FALSE;
	}else if(session->playing)
		session->playing = FALSE;
	*size = usize;
	return data;
}

int rspSessionPlayTaskPush(struct rspSession *session, char** msg, cJSON **meta, unsigned char **data, unsigned char rebuffer, float rb_threshold)
{
	int result;
	unsigned int size;
	unsigned char rsp_err;
	cJSON *item;
	struct timespec now, ts_diff;
	
	// This is a "Push Mode" playtask: It handles interleaver filling from the network and stream data reading in a single thread. 
	// The loop it is called in must not blocked external to this function so that this function can handle stream and network  
	// timing.  This function will push data out at the correctly timed pace based on the measured average stream data rate.
	
	// If you can not guarantee this function will be called with out delay (i.e. no blocking) again after it returns, than you 
	// need to use a two threaded pull based approach with using the rspSessionPlayTaskPull and rspSessionFillTask functions.
	
	// called with *data = NULL to wait for more network data to come in
	// called with *data set to last returned data block to see if there is more stream data to process
	
	// returns data size with *data set to memory location if there is stream data to process or < 0 for error.
	// See code below of negative return value meanings.
	// *msg and *meta will be set on return if there is meta data or a message to process.
	// If *msg string is set on return, the caller is responsable for freeing it.
	
	rsp_err = RSP_ERROR_NONE;
	*msg = NULL;
	*meta = NULL;
	
	if(!session->lastWrTime.tv_sec && !session->lastWrTime.tv_nsec)
		clock_gettime(CLOCK_MONOTONIC, &session->lastWrTime);
	
	if(*data == NULL)
		rsp_err = rspSessionFillTask(session, msg, &session->lastWrTime);

	clock_gettime(CLOCK_MONOTONIC, &now);
	timespec_diff(&session->lastWrTime, &now, &ts_diff);
	if(ts_diff.tv_sec > session->timeout){
		// network time-out since last write
		*data = NULL;
		return -4;
	}else if((rebuffer && (rsp_err == RSP_ERROR_FORMAT)) || (rsp_err == RSP_ERROR_RESET)){
		// Indicating change in stream format or transmit format reset.
		*data = NULL;
		return -2;
	}else if(rsp_err == RSP_ERROR_NETWORK){
		// network error
		*data = NULL;
		return -3;
	}
			
	if(rebuffer && (rspSessionGetBalance(session) <= rb_threshold)){
		clock_gettime(CLOCK_MONOTONIC, &session->lastRdTime);
		// No more data to read
		result = 0;	
		*data = NULL;
	}else if(rsp_err == RSP_ERROR_NONE){
		if(*data = rspSessionPacedReadData(session, &size, &session->lastRdTime)){
			if(size){
				// check for new meta data
				if(*meta = rspSessionNextMetadata(session)){
					if(session->relay && (item = cJSON_GetObjectItem(*meta, "Cluster")))
						//new cluster list metadata	
						rspSessionClusterSetup(session, item);					
				}
				result = size;
			}else{
				result = -1;
				*data = NULL;
			}
		}else{
			// No data to read at this time
			result = 0;	
			*data = NULL;
		}
	}else{
		result = 0;	
		*data = NULL;
	}
	if(session->wrRate > 0.0){
		// set new network read timeout, 1/2 the write period		
		float i;
		struct timeval tv;

		tv.tv_usec = modff(0.5 * session->wrRate, &i) * 1.0e6;
		tv.tv_sec = i;
		setsockopt(session->clientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
	}
	return result;
}

unsigned char rspPacketRecvrRequestSend(struct rspSession *session, struct sockaddr_in6 *addr, unsigned char start)
{
	cJSON *data, *ipGrp, *relayItem;
	char *data_str, ipStr[48];
	unsigned int size;
	unsigned char err;
	struct sockaddr_in *tmp_addr;
	struct clusterRecord *rec;	
	
	if(session->clientSocket < 0)
		return RSP_ERROR_NETWORK;
	
	data_str = NULL;
	data = NULL;
	ipGrp = NULL;
	err = RSP_ERROR_INIT;
	if(session->rrAddr.sin6_port){
		if((data = cJSON_CreateObject()) && (ipGrp = cJSON_CreateObject())){
			if(session->clientName)
				cJSON_AddStringToObject(data, "Client", session->clientName);			
			if(session->streamName)
				cJSON_AddStringToObject(data, "Stream", session->streamName);			
			if(start){
				cJSON_AddTrueToObject(data, "start");
			}else{
				cJSON_AddTrueToObject(data, "stop");
			}
			if(session->bindAddr.sin6_family == AF_INET){
				tmp_addr = (struct sockaddr_in *)&session->bindAddr;
				if(inet_ntop(AF_INET, &(tmp_addr->sin_addr), ipStr, sizeof(ipStr)))
					cJSON_AddStringToObject(ipGrp, "Addr", ipStr);
				else 
					goto fail;
				cJSON_AddNumberToObject(ipGrp, "Port", ntohs(tmp_addr->sin_port));
				if(session->m_grp)
					cJSON_AddStringToObject(ipGrp, "Mcast", session->m_grp);
				if(session->relay_cluster){
					cJSON_AddNumberToObject(ipGrp, "Relay",session->relay);
				}else{
					if(session->relay)
						cJSON_AddTrueToObject(ipGrp, "Relay");
					else
						cJSON_AddFalseToObject(ipGrp, "Relay");
				}
				cJSON_AddItemToObject(data, "IP4", ipGrp);
				
			}else if(session->bindAddr.sin6_family == AF_INET6){
				if(inet_ntop(AF_INET6, &session->bindAddr.sin6_addr, ipStr, sizeof(ipStr)))
					cJSON_AddStringToObject(ipGrp, "Addr", ipStr);
				else
					goto fail;
				cJSON_AddNumberToObject(ipGrp, "Port", ntohs(session->bindAddr.sin6_port));
				if(session->m_grp)
					cJSON_AddStringToObject(ipGrp, "Mcast", session->m_grp);
				if(session->relay_cluster){
					cJSON_AddNumberToObject(ipGrp, "Relay",session->relay);
				}else{
					if(session->relay)
						cJSON_AddTrueToObject(ipGrp, "Relay");
					else
						cJSON_AddFalseToObject(ipGrp, "Relay");
				}
				cJSON_AddItemToObject(data, "IP6", ipGrp);
				
			}else
				goto fail;
			
			if(!addr && session->relay_cluster && session->relay && (rec = session->clusterList) && (relayItem = cJSON_GetObjectItem(ipGrp, "Relay"))){
				cJSON_AddNumberToObject(ipGrp, "RClu", session->relay_cluster);
				relayItem->valueint = 1;
				relayItem->valuedouble = 1;
				while((rec = rec->next) && (data_str = cJSON_PrintUnformatted(data))){
					size = strlen(data_str) + 1;
					if((size > 0) && (size <= 240)){
						if(size % 16)
							size = size + 16;
						size = (size / 16) * 16;
						bzero(session->rsp_checksum_packet, size + 1);
						session->rsp_checksum_packet[0] = RSP_FLAG_RR | ((size - 16) & 0xF0);
						memcpy(session->rsp_checksum_packet + 1, data_str, size);
						rspSendto(session->clientSocket, session->rsp_checksum_packet, size + 1, 0, (struct sockaddr*)&rec->host);
					}
					if(!rec->suspend){
						relayItem->valueint++;
						relayItem->valuedouble++;
					}
					free(data_str);
				}
				session->relay = 1;
				cJSON_Delete(data);
				return RSP_ERROR_NONE;

			}else{
				if(data_str = cJSON_PrintUnformatted(data)){
					// format packet and send
					size = strlen(data_str) + 1;
					if((size > 0) && (size <= 240)){
						if(size % 16)
							size = size + 16;
						size = (size / 16) * 16;
						bzero(session->rsp_checksum_packet, size + 1);
						session->rsp_checksum_packet[0] = RSP_FLAG_RR | ((size - 16) & 0xF0);
						memcpy(session->rsp_checksum_packet + 1, data_str, size);
						if(addr){
							rspSendto(session->clientSocket, session->rsp_checksum_packet, size + 1, 0, (struct sockaddr*)addr);
						}else{
							rspSendto(session->clientSocket, session->rsp_checksum_packet, size + 1, 0, (struct sockaddr*)&session->rrAddr);
							if(session->rrAddr2.sin6_port)
								// send to secondary server as well (for redundent stream)
								rspSendto(session->clientSocket, session->rsp_checksum_packet, size + 1, 0, (struct sockaddr*)&session->rrAddr2);
						}
						free(data_str);
						cJSON_Delete(data);
						return RSP_ERROR_NONE;
					}
					free(data_str);
				}
			}
			ipGrp = NULL;
		}
	}
	err = RSP_ERROR_MISSING;
	
fail:
	if(data)
		cJSON_Delete(data);
	if(ipGrp)
		cJSON_Delete(ipGrp);
	if(data_str)
		free(data_str);
	return err;
}

unsigned short rspPacketInit(unsigned char *packet, unsigned char flags, unsigned short payload_size, unsigned char *netRoots)
{
	// returns packet_size if no error
	// returns 0 on error
	
	unsigned short size;
	
	size = 0;
	// packet header, byte 1: flaggs and payload size
	packet[0] = 0x0F & flags;
	// check payload size
	if(payload_size < 16)
		return 0;
	if(flags & RSP_FLAG_RS){
		if(payload_size > 240)
			return 0;
		else
			if(payload_size > 256)
				return 0;
	}
	if(payload_size & 0x0F)	// must be an integer multiple of 16 (lower 4 bits = 0)
		return 0;
	
	packet[0] |= (unsigned char)(payload_size - 16);
	size++;
	
	// packet header, byte 2: interleaver block number (set to zero) 
	packet[1] = 0;
	size++;
	
	// packet header, byte 3: column index
	packet[2] = 0xFF;	// 0xFF indicates start of a new transmission... receivers should reset interleaver.	
	size++;
	
	// finally, calculate packet size to return, etc.
	size = size + payload_size;
	if(flags & RSP_FLAG_CRC)
		size = size + 4;	// four more bytes for crc at end
	
	if(flags & RSP_FLAG_RS){
		if(netRoots)
			*netRoots = size - 1;	// the rs encoder needs to encode the whole packet less first packet header byte
		size = 256;
	}
	return size;
}

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
unsigned char rspPacketReadHeader(unsigned char *packet, unsigned short size, unsigned char *flags, unsigned short *payload_size, unsigned char *col, unsigned char *block, struct rs *rs_session, RSA *rsa, unsigned int *crc_table)
#else
unsigned char rspPacketReadHeader(unsigned char *packet, unsigned short size, unsigned char *flags, unsigned short *payload_size, unsigned char *col, unsigned char *block, struct rs *rs_session, void *rsa, unsigned int *crc_table)
#endif
{
	unsigned short netRoots;
	
	if(size < 3)
		return RSP_ERROR_SIZE;
	
	*flags = packet[0] & 0x0F;
	// payload size
	*payload_size = packet[0] & 0xF0;
	*payload_size = *payload_size + 16;
	
	if((*flags & 0x03) == RSP_FLAG_AUTH){
		// check some things...
		if(((*flags & RSP_FLAG_CRC) == 0) && rsa)
			return RSP_ERROR_FORMAT;	// auth packets MUST have CRC
		if(size != 277)
			return RSP_ERROR_SIZE;	// invalid size for authenrtication packet

		unsigned char msg[256];
        
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
		if(!rsa || (RSA_public_decrypt(272, packet + 1, msg, rsa, RSA_PKCS1_PADDING) != 256))
			return RSP_ERROR_RSA;
#endif
		memcpy(packet + 1, msg, 256);
		// and move the CRC32 chunk back 16 bytes, the RSA padding for PKCS1
		memmove(packet + 257, packet + 273, 4);
		*payload_size = 254;
		size = 261;
		
		// an auth packet has the block number in second packet byte after decrypting
		*block = packet[1];
		// the CRC will be checked next
		
	}else if(*flags & RSP_FLAG_RS){
		// the rs decoder needs to decode the whole packet less first packet header byte or extended packet header bytes
		netRoots = *payload_size + 2;	
		if(*flags & RSP_FLAG_CRC)
			netRoots = netRoots + 4;
		// validate size
		if(size != 256)
			return RSP_ERROR_SIZE;
		// decode rs
		if(rs_session == NULL)
			return RSP_ERROR_FORMAT;
		if(rs_session->nroots != (255 - netRoots))
			return RSP_ERROR_FORMAT;
		if((*flags & 0x03) == RSP_FLAG_EXT){
			if(decode_rs_char(rs_session, packet+3, NULL, 0) < 0)
				return RSP_ERROR_RS;
			size = netRoots + 3; 				
		}else{
			if(decode_rs_char(rs_session, packet+1, NULL, 0) < 0)
				return RSP_ERROR_RS;
			size = netRoots + 1; 				
		}
	}
	
	// validate size
	if(*flags & RSP_FLAG_CRC){
		if(((*flags & 0x03) == RSP_FLAG_PAYLOAD) && (size != *payload_size + 7))
			return RSP_ERROR_SIZE;
		if(((*flags & 0x03) == RSP_FLAG_EXT) && (size != *payload_size + 9))
			return RSP_ERROR_SIZE;
		// check CRC
		// calculate CRC32 on whole packet
		unsigned int t2;
		t2 = *((unsigned int*)(&packet[size-4]));
		if(htonl(chksum_crc32(packet, size-4, crc_table)) != t2)
			return RSP_ERROR_CRC;
	}else if((*flags & 0x03) == RSP_FLAG_RR){
		if(size != *payload_size + 1)
			return RSP_ERROR_SIZE;
	}else if((*flags & 0x03) == RSP_FLAG_EXT){
		if(size != *payload_size + 5)
			return RSP_ERROR_SIZE;
	}else{
		if(size != *payload_size + 3)
			return RSP_ERROR_SIZE;
	}
	
	if((*flags & 0x03) == RSP_FLAG_RR)
		return RSP_ERROR_RRPCKT;

	if((*flags & 0x03) == RSP_FLAG_PAYLOAD){
		// block address
		*block = packet[1];
		// collumn address
		*col = packet[2];
	}
	if((*flags & 0x03) == RSP_FLAG_EXT){
		// block address
		*block = packet[3];
		// collumn address
		*col = packet[4];
	}
	return RSP_ERROR_NONE;
}

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
unsigned short rspPacketResetSet(unsigned char *packet, struct rs *rs_session, RSA *rsa, unsigned int *crc_table)
#else
unsigned short rspPacketResetSet(unsigned char *packet, struct rs *rs_session, void *rsa, unsigned int *crc_table)
#endif
{
	unsigned short pl_size;
	unsigned short size;

	pl_size = packet[0] & 0xF0;
	pl_size = pl_size + 16;

	// set column nuber to reset flag (0xFF), which is an invalid column number indicating reset
	packet[2] = 0xFF;
	// set block nuber to random number
	packet[1] = random() & 0xFF;
	// zero payload portion of the packet
	bzero(packet + 3, pl_size);

/*	if(rsa){
		// and set an RSA private encrypted payload representing the single byte currently in second packet byte
		// for oprtional reset packet authentication
		long result;
		result = RSA_private_encrypt(1, &packet[1], packet + 3, rsa, RSA_PKCS1_PADDING);
	}
 */
	size = 3 + pl_size;

	// set optional CRC
	if(packet[0] & RSP_FLAG_CRC){
		unsigned int crc;
		
		// calculate CRC32 on three byte header and payload
		crc = chksum_crc32(packet, size, crc_table);
		packet[size++] = (unsigned char)((crc >> 24) & 0x000000FF);	// most significant crc byte
		packet[size++] = (unsigned char)((crc >> 16) & 0x000000FF);	// high crc byte
		packet[size++] = (unsigned char)((crc >> 8) & 0x000000FF);	// low crc byte
		packet[size++] = (unsigned char)(crc & 0x000000FF);			// least significant crc byte		
	}
	
	// apply optional RS coding
	if(rs_session && (packet[0] & RSP_FLAG_RS)){
		// encoding begins at the SECOND or FOURTH header byte, and includes the payload and optional 
		// CRC32 bytes. Assumtion: The rs_session was setup to read the correct number of bytes.
		// rs encoded packets are always 255 bytes plus the unencoded original first byte.  Copy the encoded bytes after first header byte.
		if((packet[0] & 0x03) == RSP_FLAG_EXT)
			encode_rs_char(rs_session, packet + 3, packet + size - 2);	 
		else
			encode_rs_char(rs_session, packet + 1, packet + size);	
		size = 256;
	}
	
	return size;
}

unsigned short rspPacketPayloadSet(unsigned char *packet, unsigned char *payload, struct rs *rs_session, unsigned char column, unsigned char block, unsigned char ex_fec, unsigned char ex_il, unsigned int *crc_table)
{
	// assumes rspPacketInit has already been called to initialize the packet header fields
	// if the ex_ parameters are non-zero, then the packet is set as an extended payload packet
	
	unsigned short pl_size;
	unsigned short size;
	
	// get payload size
	if(ex_il || ex_fec)
		// set packet type as extended payload, keep size and other flags intacted
		packet[0] = (packet[0] & 0xFC) + RSP_FLAG_EXT;
	else
		// set packet type as normal payload, keep size and other flags intacted
		packet[0] = (packet[0] & 0xFC) + RSP_FLAG_PAYLOAD;

	pl_size = packet[0] & 0xF0;
	pl_size = pl_size + 16;
	
	
	if((packet[0] & 0x03) == RSP_FLAG_EXT){
		packet[1] = ex_fec;
		packet[2] = ex_il;
		packet[3] = block;
		packet[4] = column;
		
		if(payload)
			// copy payload bytes
			memcpy(packet + 5, payload, pl_size);
		else
			return 0;
		
		size = 5 + pl_size;
	}else{
		// set interleaver coordinates
		packet[1] = block;
		packet[2] = column;
		
		if(payload)
			// copy payload bytes
			memcpy(packet + 3, payload, pl_size);
		else
			return 0;
		
		size = 3 + pl_size;
	}

	// set optional CRC
	if(packet[0] & RSP_FLAG_CRC){
		unsigned int crc;
		
		// calculate CRC32 on three or five byte header and payload
		crc = chksum_crc32(packet, size, crc_table);
		packet[size++] = (unsigned char)((crc >> 24) & 0x000000FF);	// most significant crc byte
		packet[size++] = (unsigned char)((crc >> 16) & 0x000000FF);	// high crc byte
		packet[size++] = (unsigned char)((crc >> 8) & 0x000000FF);	// low crc byte
		packet[size++] = (unsigned char)(crc & 0x000000FF);			// least significant crc byte		
	}
	
	// apply optional RS coding
	if(rs_session && (packet[0] & RSP_FLAG_RS)){
		// encoding begins at the SECOND or FOURTH header byte, and includes the payload and optional 
		// CRC32 bytes. Assumtion: The rs_session was setup to read the correct number of bytes.
		// rs encoded packets are always 255 bytes plus the unencoded original first byte.  Copy the encoded bytes after first header byte.
		if((packet[0] & 0x03) == RSP_FLAG_EXT)
			encode_rs_char(rs_session, packet + 3, packet + size - 2);	 
		else
			encode_rs_char(rs_session, packet + 1, packet + size);	
		size = 256;
	}
		
	return size;	
}

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
unsigned short rspPacketSignedChecksumsSet(unsigned char *packet, unsigned char *check_sums, unsigned char block, RSA *rsa, unsigned int *crc_table)
{
	unsigned int crc;
	unsigned short size;
	unsigned char msg[256];
	
	if(!rsa)
		return 0;
	size = 277;
	// packet header, byte 1: auth and crc flags with payload size field set to 0xF0
	packet[0] = RSP_FLAG_AUTH | RSP_FLAG_CRC | 0xF0;	
	// block number + copy 255 checksums
	packet[1] = block;
	memcpy(packet + 2, check_sums, 255);
	
	// calculate and set set CRC32
	crc = chksum_crc32(packet, 257, crc_table);
	packet[273] = (unsigned char)((crc >> 24) & 0x000000FF);	// most significant crc byte
	packet[274] = (unsigned char)((crc >> 16) & 0x000000FF);	// high crc byte
	packet[275] = (unsigned char)((crc >> 8) & 0x000000FF);		// low crc byte
	packet[276] = (unsigned char)(crc & 0x000000FF);			// least significant crc byte
	
	memcpy(msg, packet + 1, 256);
	// and encrypt the 256 payload bytes into the packet
	if(RSA_private_encrypt(256, msg, packet + 1, rsa, RSA_PKCS1_PADDING) == 272)
		return size;
	return 0;
}
#endif

unsigned char rspPacketRecvrReportRequestGet(unsigned char *packet, struct sockaddr_in6 *fromAddress, struct recvrRecord *recvrRecord)
{
	// this function assumes the packet header has already been read to verify that this is a valid rr packet!
	
	char *str;
	cJSON *root, *group, *item;
	unsigned char size;
	size_t len;
	struct sockaddr_in *addr;

	root = NULL;
	if(recvrRecord == NULL)
		return RSP_ERROR_MISSING;
	bzero(recvrRecord, sizeof(struct recvrRecord));
	size = (packet[0] & 0xF0) + 16;
	packet[size] = 0;	// make damn sure the packet is null terminated!
	str = (char *)(packet + 1);

	if(root = cJSON_Parse(str)){
		recvrRecord->meta = root;
		// get request state, if any
		if((item = cJSON_GetObjectItem(root, "start")) && (item->valueint))
				recvrRecord->start_stop_request = RSP_RR_STATE_START;
		else if((item = cJSON_GetObjectItem(root, "stop")) && (item->valueint))
				recvrRecord->start_stop_request = RSP_RR_STATE_STOP;
		else
			recvrRecord->start_stop_request = RSP_RR_STATE_NONE;

		// get IP address record
		if(group = cJSON_GetObjectItem(root, "IP6")){
			recvrRecord->statedAddress.sin6_family = AF_INET6;
			if(item = cJSON_GetObjectItem(group, "Port"))
			   recvrRecord->statedAddress.sin6_port = htons(item->valueint);
			else
			   goto fail;
			if(item = cJSON_GetObjectItem(group, "Addr"))
				inet_pton(AF_INET6, item->valuestring, &recvrRecord->statedAddress.sin6_addr);
			else{
				if(item = cJSON_GetObjectItem(group, "Address"))
					inet_pton(AF_INET6, item->valuestring, &recvrRecord->statedAddress.sin6_addr);
				else
					goto fail;
			}
			
			recvrRecord->m_grp = NULL;
			if(item = cJSON_GetObjectItem(group, "Mcast")){
				if(item->valuestring && (len = strlen(item->valuestring))){
					recvrRecord->m_grp = (char *)malloc(len + 1);
					strcpy(recvrRecord->m_grp, item->valuestring);
				}
			}else{
				if(item = cJSON_GetObjectItem(group, "Multicast")){
					if(item->valuestring && (len = strlen(item->valuestring))){
						recvrRecord->m_grp = (char *)malloc(len + 1);
						strcpy(recvrRecord->m_grp, item->valuestring);
					}
				}				
			}
			recvrRecord->via = NULL;
			if(item = cJSON_GetObjectItem(group, "Via")){
				if(item->valuestring && (len = strlen(item->valuestring))){
					recvrRecord->via = (char *)malloc(len + 1);
					strcpy(recvrRecord->via, item->valuestring);
				}
			}
			recvrRecord->relay = 0;
			recvrRecord->relay_cluster = 0;
			if(item = cJSON_GetObjectItem(group, "Relay")){
				if(item->type == cJSON_True){
					recvrRecord->relay = 1;
				}
				if(item->type == cJSON_Number){
					recvrRecord->relay = item->valueint;
					if(item = cJSON_GetObjectItem(group, "RClu"))
						recvrRecord->relay_cluster = item->valueint;						
				}
			}
			
		}else if(group = cJSON_GetObjectItem(root, "IP4")){
			addr = (struct sockaddr_in *)&recvrRecord->statedAddress;

			addr->sin_family = AF_INET;
			if(item = cJSON_GetObjectItem(group, "Port"))
				addr->sin_port = htons(item->valueint);
			else
			   goto fail;

			if(item = cJSON_GetObjectItem(group, "Addr"))
				inet_pton(AF_INET, item->valuestring, &addr->sin_addr);
			else{
				if(item = cJSON_GetObjectItem(group, "Address"))
					inet_pton(AF_INET, item->valuestring, &addr->sin_addr);
				else
					goto fail;				
			}
			
			recvrRecord->m_grp = NULL;
			if(item = cJSON_GetObjectItem(group, "Mcast")){
				if(item->valuestring && (len = strlen(item->valuestring))){
					recvrRecord->m_grp = (char *)malloc(len + 1);
					strcpy(recvrRecord->m_grp, item->valuestring);
				}
			}else{
				if(item = cJSON_GetObjectItem(group, "Multicast")){
					if(item->valuestring && (len = strlen(item->valuestring))){
						recvrRecord->m_grp = (char *)malloc(len + 1);
						strcpy(recvrRecord->m_grp, item->valuestring);
					}
				}
			}
			recvrRecord->via = NULL;
			if(item = cJSON_GetObjectItem(group, "Via")){
				if(item->valuestring && (len = strlen(item->valuestring))){
					recvrRecord->via = (char *)malloc(len + 1);
					strcpy(recvrRecord->via, item->valuestring);
				}
			}
			recvrRecord->relay = 0;
			recvrRecord->relay_cluster = 0;
			if(item = cJSON_GetObjectItem(group, "Relay")){
				if(item->type == cJSON_True){
					recvrRecord->relay = 1;
				}
				if(item->type == cJSON_Number){
					recvrRecord->relay = item->valueint;
					if(item = cJSON_GetObjectItem(group, "RClu"))
						recvrRecord->relay_cluster = item->valueint;						
				}
			}
			
		}else{
			// either IP4 or IP6 info is required!
			goto fail;
		}
			
		recvrRecord->apparentAddress = *fromAddress;
		
		// set report values, if any
		if(group = cJSON_GetObjectItem(root, "Report")){
			if(item = cJSON_GetObjectItem(group, "Fix"))
			   recvrRecord->FECStat = item->valuedouble;
			else if(item = cJSON_GetObjectItem(group, "Fixed"))
				recvrRecord->FECStat = item->valuedouble;
			if(item = cJSON_GetObjectItem(group, "Fail"))
				  recvrRecord->ErrStat = item->valuedouble;
			else if(item = cJSON_GetObjectItem(group, "Failed"))
				recvrRecord->ErrStat = item->valuedouble;
			if(item = cJSON_GetObjectItem(group, "Bad"))
				recvrRecord->BadStat = item->valuedouble;
			else if(item = cJSON_GetObjectItem(group, "BadPkt"))
				recvrRecord->BadStat = item->valuedouble;
			if(item = cJSON_GetObjectItem(group, "Dup"))
				recvrRecord->DupStat = item->valuedouble;
			else if(item = cJSON_GetObjectItem(group, "DupPkt"))
				recvrRecord->DupStat = item->valuedouble;
			if(item = cJSON_GetObjectItem(group, "Bal"))
				recvrRecord->BalStat = item->valuedouble;
			if(item = cJSON_GetObjectItem(group, "Stat"))
				recvrRecord->status = item->valueint;
			else
				recvrRecord->status = FALSE;
		}
		// note the time we heard from this receiver (now)
		recvrRecord->lastHeard = time(NULL);
		return RSP_ERROR_NONE;
	}
fail:
	rspRecvrReportFree(recvrRecord);
	return RSP_ERROR_FORMAT;	
	
}

void rspRecvrReportFree(struct recvrRecord *recvrRecord)
{
	if(recvrRecord){
		// free any strings and such we may have allocated in the process of populating the record
		if(recvrRecord->m_grp)
			free(recvrRecord->m_grp);
		if(recvrRecord->via)
			free(recvrRecord->via);
		if(recvrRecord->meta)
			cJSON_Delete(recvrRecord->meta);	
	}
}

unsigned short rspPacketRecvrReportSet(struct rspSession *session, unsigned char force_relay)
{
	cJSON *data, *ipGrp, *rr;
	char *data_str, ipStr[49];
	unsigned int size;
	struct sockaddr_in *addr;
	
	rr = NULL;
	ipGrp = NULL;
	data_str = NULL;
	data = NULL;
	
	if((data = cJSON_CreateObject()) && (ipGrp = cJSON_CreateObject()) && (rr = cJSON_CreateObject())){
		if(session->clientName)
			cJSON_AddStringToObject(data, "Client", session->clientName);
		if(session->streamName)
			cJSON_AddStringToObject(data, "Stream", session->streamName);
		if(session->bindAddr.sin6_family == AF_INET){
			addr = (struct sockaddr_in *)&session->bindAddr;

			if(inet_ntop(AF_INET, &(addr->sin_addr), ipStr, sizeof(ipStr)))
				cJSON_AddStringToObject(ipGrp, "Addr", ipStr);
			else 
				goto fail;
			if(force_relay)
				cJSON_AddNumberToObject(ipGrp, "Port", ntohs(0));
			else
				cJSON_AddNumberToObject(ipGrp, "Port", ntohs(addr->sin_port));
			if(session->m_grp)
				cJSON_AddStringToObject(ipGrp, "Mcast", session->m_grp);
			if(session->relay){
				cJSON_AddNumberToObject(ipGrp, "Relay", session->relay);
				if(session->relay_cluster)
					cJSON_AddNumberToObject(ipGrp, "RClu", session->relay_cluster);
			}else
				cJSON_AddFalseToObject(ipGrp, "Relay");
			
			cJSON_AddItemToObject(data, "IP4", ipGrp);
			ipGrp = NULL;			
			
		}else if(session->bindAddr.sin6_family == AF_INET6){
			if(inet_ntop(AF_INET6, &session->bindAddr.sin6_addr, ipStr, sizeof(ipStr)))
				cJSON_AddStringToObject(ipGrp, "Addr", ipStr);
			else
				goto fail;
			if(force_relay)
				cJSON_AddNumberToObject(ipGrp, "Port", ntohs(0));
			else
				cJSON_AddNumberToObject(ipGrp, "Port", ntohs(addr->sin_port));
			if(session->m_grp)
				cJSON_AddStringToObject(ipGrp, "Mcast", session->m_grp);
			if(session->relay){
				cJSON_AddNumberToObject(ipGrp, "Relay", session->relay);
				if(session->relay_cluster)
					cJSON_AddNumberToObject(ipGrp, "RClu", session->relay_cluster);
			}else
				cJSON_AddFalseToObject(ipGrp, "Relay");
			cJSON_AddItemToObject(data, "IP6", ipGrp);
			ipGrp = NULL;
			
		}else
			goto fail;
		if(session->FECroots)
			cJSON_AddNumberToObject(rr, "Fix", round(100. * session->FECStat / session->FECroots));		// % fixed bytes per frame
		else
			cJSON_AddNumberToObject(rr, "Fix", 0);		
		cJSON_AddNumberToObject(rr, "Fail", round(session->ErrStat * 100.));	// % fail frames
		cJSON_AddNumberToObject(rr, "Bad", round(session->BadStat * 100.));	// % bad packets
		cJSON_AddNumberToObject(rr, "Dup", round(session->DupStat * 100.));	// % duplicate packets
		cJSON_AddNumberToObject(rr, "Bal", round(rspSessionGetBalance(session) * 100.)); // % read-write balance, + ahead, - behind.
		if(session->playing)
			cJSON_AddTrueToObject(rr, "Stat");
		else
			cJSON_AddFalseToObject(rr, "Stat");
		cJSON_AddItemToObject(data, "Report", rr);
		rr = NULL;

		if(data_str = cJSON_PrintUnformatted(data)){
			// format packet and send
			size = strlen(data_str) + 1;
			if((size > 0) && (size <= 240)){
				if(size % 16)
					size = size + 16;
				size = (size / 16) * 16;
				bzero(session->rsp_checksum_packet, size + 1);
				session->rsp_checksum_packet[0] = RSP_FLAG_RR | ((size - 16) & 0xF0);
				memcpy(session->rsp_checksum_packet + 1, data_str, strlen(data_str));
				free(data_str);		
				cJSON_Delete(data);
				return size + 1;
			}
			free(data_str);
		}
		cJSON_Delete(data);
		data = NULL;
	}
		
fail:
	if(data)
		cJSON_Delete(data);
	if(rr)
		cJSON_Delete(rr);
	if(ipGrp)
		cJSON_Delete(ipGrp);

	if(data_str)
		free(data_str);
	return 0;	
}

// interleaver functions

struct interleaver *il_init(unsigned short row_n, unsigned short col_n, unsigned char ratio)
{
	struct interleaver *il;
	size_t len;
	
	il = (struct interleaver *)malloc(sizeof(struct interleaver));
	
	il->rows = row_n;
	il->columns = col_n;
	il->ratio = ratio;
	
	len = (il->columns + 1) * il->ratio * 3;
	il->col_checksums = (unsigned char *)malloc(len);
	
	len = len * il->rows;
	il->storage = (unsigned char *)malloc(len);

	len = (il->columns) * il->ratio * 3;
	il->col_erasures = (unsigned char *)malloc(len);
	
	il_reset(il);
	
	return il;
}

void il_free(struct interleaver *il)
{
	free(il->storage);
	free(il->col_checksums);
	free(il->col_erasures);
	free(il);
}

void il_reset(struct interleaver *il)
{
	size_t len;

	il->rowIdx = 0;
	il->rowBlock = 0;
	il->colIdx = 0;
	il->colBlock = 0;
	il->rwBalance = 0;
	
	len =  (il->columns + 1) * il->ratio * 3;
	bzero(il->col_checksums, len);	

	len =  (il->columns) * il->ratio * 3;
	bzero(il->col_erasures, len);

	len = len * il->rows;
	bzero(il->storage, len);	
}

void il_clearBlock(struct interleaver *il, unsigned char block)
{
// no need to clear the actual storage... just the checksums and erasures.
// infact, we want to leave storage intact so it can be used by the end application.
	
	bzero(il->col_checksums+((il->columns + 1) * block), il->columns + 1);
	bzero(il->col_erasures+((il->columns) * block), il->columns);
}

unsigned char il_rowColumnOverlap(struct interleaver *il)
{
	// the storage area is divided into multiple logical blocks to allow reading from one block while filling another block
	if((il->rowBlock / il->ratio) == (il->colBlock / il->ratio))
		// current row and column indicators are with in the same logical block reading and writing will collide.
		return 1;
	// current row and column indicators are in different logical block, read/write OK.
	return 0;
}

unsigned char* il_getRow(struct interleaver *il, unsigned short row, unsigned char block)
{
	size_t offset;
	
	// block offset
	offset = il->rows * il->columns * block;
	
	// add row offset
	offset = offset + (row * il->columns);
	
	return il->storage + offset;
}

unsigned char* il_getCurRow(struct interleaver *il)
{	
	return il_getRow(il, il->rowIdx, il->rowBlock);
}

unsigned char il_nextRow(struct interleaver *il)
{
	// returns 1 if we crossed a logical block boundry
	il->rowIdx++;
	if(il->rowIdx >= il->rows){
		il->rowIdx = 0;
		il->rowBlock++;
		if(il->rowBlock >= (il->ratio * 3))
			il->rowBlock = 0;
		if((il->rowBlock % il->ratio) == 0)
			return 1;	// crossed a logical block boundry
		return 0;
	}
	return 0;
}

void il_copyColumn(struct interleaver *il, unsigned char *data, unsigned short col, unsigned char block)
{
	size_t offset;
	int i;
	
	// block offset
	offset = il->rows * il->columns * block;
	
	// add column offset
	offset = offset + col;
	
	for(i=0; i<il->rows; i++){
		data[i] = il->storage[offset];
		offset = offset + il->columns;
	}
}

void il_copyCurColumn(struct interleaver *il, unsigned char *data)
{
	il_copyColumn(il, data, il->colIdx, il->colBlock);
}

unsigned char il_writeColumn(struct interleaver *il, unsigned char *data, unsigned short col, unsigned char block, unsigned char extended)
{
	size_t offset;
	unsigned char *erasure;
	int i;
		
	// block offset
	offset = il->rows * il->columns * block;
	
	// add column offset
	offset = offset + col;
	
	for(i=0; i<il->rows; i++){
		il->storage[offset] = data[i];
		offset = offset + il->columns;
	}
	
	// Mark column as received, so we know where bit erasures have NOT occured.
	// All unmarked colums can then be flagged as erasues when we go to decode a row's RS data.
	erasure = il->col_erasures + ((il->columns) * block) + col;
	if(*erasure){
		// already filled
		return 0;
	}
	if(extended)
		*erasure = 2;
	else{
		*erasure = 1;
		il->colIdx = col;
		il->colBlock = block;
	}
	
	return 1;
}

void il_writeCurColumn(struct interleaver *il, unsigned char *data)
{
	il_writeColumn(il, data, il->colIdx, il->colBlock, 0);
}

unsigned char il_nextColumn(struct interleaver *il)
{
	// returns 1 if we crossed a logical block boundry
	return il_incColumn(il, &il->colIdx, &il->colBlock);
}

unsigned char il_incColumn(struct interleaver *il, unsigned short *col, unsigned char *blk)
{
	// returns 1 if we crossed a logical block boundry
	(*blk)++;
	if((*blk % il->ratio) == 0){
		(*col)++;
		if(*col >= il->columns){
			*col = 0;
			*blk = *blk % (il->ratio * 3);
			return 1;	// crossed a logical block boundry
		}else
			*blk = *blk - il->ratio;
	}
	return 0;
}

void il_updateBlockChecksums(struct interleaver *il, unsigned char block)
{
	int i;
	size_t offset;
	unsigned char *dataPtr;
	
	offset = (il->columns + 1) * block;
	dataPtr = (unsigned char*)malloc(il->rows);
	for(i=0; i<il->columns; i++){
		// copy column data to get checksum on
		il_copyColumn(il, dataPtr, i, block);
		// get and store the checksum
		il->col_checksums[offset + i] = checkSum(dataPtr, il->rows);
	}
	il->col_checksums[offset + i] = 1; // flag checksums as valid
	free(dataPtr);
}

void il_receiverChecksums(struct interleaver *il, unsigned char block, unsigned char *checksums)
{
	size_t offset;
	
	offset = (il->columns + 1) * block;
	memcpy(il->col_checksums + offset, checksums, il->columns);
	*(il->col_checksums + offset + il->columns) = 1;  // flag checksums as valid
}

unsigned char il_getChecksum(struct interleaver *il, unsigned short col, unsigned char block)
{
	return il->col_checksums[((il->columns + 1) * block) + col];
}

unsigned char *il_getChecksums(struct interleaver *il, unsigned char block)
{
	return il->col_checksums + ((il->columns + 1) * block);
}

unsigned char il_getChecksumValid(struct interleaver *il, unsigned char block)
{
	return il->col_checksums[((il->columns + 1) * block) + il->columns];
}

unsigned char il_getBlockErasures(struct interleaver *il, unsigned char block, unsigned char *erasures)
{	
	unsigned char i, count;
	unsigned char *ptr;
	
	ptr = il->col_erasures + ((il->columns) * block);
	count = 0;
	for(i=0; i<il->columns; i++){
		if(*(ptr + i) == 0){
			erasures[count] = i;
			count++;
		}
	}
	return count;
}
