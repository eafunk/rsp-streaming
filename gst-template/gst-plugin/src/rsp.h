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

#ifndef __RSP_H
#define __RSP_H 

#if defined(__APPLE__)
#include "TargetConditionals.h"
#endif

#include "rs.h"
#include "cJSON.h"

#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#endif

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

// rsp definisions 

#define RSP_FLAG_PAYLOAD	0	// this is a standard payload header

#define RSP_FLAG_AUTH		1 	// packet is a private key encrypted block ckeck sum packet for authentication
// Packet size is 261 bytes.  One byte header, 256 cheksum bytes, last set to 0, and 4 CRC32 bytes
// all other flags are ignored, and the upper four bits specify the block number this applies to.
// this packet is transmitted ahead of reading network packets out of one or more interleaver blocks
// to announce the 8 bit check sum of subsiquent packet payloads.

#define RSP_FLAG_RR			2	// this is a receiver report/request header
// the string is always 256 - 11 = 245 bytes long, padded with NULLs to fill the space.
// this allows for public key encrytpion as an option.

#define RSP_FLAG_EXT		3	// this is a extended payload header

#define RSP_FLAG_CRC	(1 << 2)	// packet header has CRC32 check-sum at end
#define RSP_FLAG_RS		(1 << 3)	// all packet bytes, except the first byte of the header, are RS(255,x) encoded
// where x = payload size (as specified in the header) + header length (3) - 1 + optional CRC, 
// not to exceed 253 and not smaller than 128
// the packet size is always 256 bytes in this mode.

#define kTargetWrRdGap	1.5

#define TRUE	1
#define FALSE	0

#define RSP_RR_STOP 0
#define RSP_RR_START 1

#define RSP_RR_STATE_STOP -1
#define RSP_RR_STATE_START 1
#define RSP_RR_STATE_NONE 0

#define RSP_ERROR_NONE 0
#define RSP_ERROR_SIZE 1
#define RSP_ERROR_CRC 2
#define RSP_ERROR_RS 3
#define RSP_ERROR_FORMAT 4
#define RSP_ERROR_KEYSIZE 5
#define RSP_ERROR_BADKEY 6
#define RSP_ERROR_PARSING 7
#define RSP_ERROR_MISSING 8
#define RSP_ERROR_INIT 9
#define RSP_ERROR_RSA 10
#define RSP_ERROR_AUTH 11
#define RSP_ERROR_DUP 12
#define RSP_ERROR_NODATA 13
#define RSP_ERROR_RRPCKT 14
#define RSP_ERROR_RESET 15
#define RSP_ERROR_WAITING 16
#define RSP_ERROR_END 17
#define RSP_ERROR_NETWORK 18
#define RSP_ERROR_WINDOW 19

struct rspDNSList {
	char			**h_addr_list;	/* address list from most recent DNS query*/	
	int				h_size;			/* byte size of host addresses */
	int				h_index;		/* current index being tried in h_addr_list array*/
};

struct clusterRecord{
	struct clusterRecord *next;
	struct	sockaddr_in6 host;
	unsigned int hash;	
	time_t	lastHeard;
	unsigned char suspend;
};

struct rspSession {
	void *referenceDesignator;
	char *clientName;
	char *streamName;
	
	pthread_mutex_t threadLock;				// a mutex for use in protection the session data structures
											// when accessed across mutiple threads of execution.
	
	unsigned int crc_table[256];
	pthread_mutex_t metaMutex;
	unsigned char relay;
	unsigned char relay_cluster;
	struct clusterRecord *clusterList;		// see relay_cluster for array count
	unsigned int cluster_timeout;
	struct sockaddr_in6 lastAddr;
	struct rspDNSList dnsList;	
	unsigned char triedIP6;
	
	cJSON *config;
	cJSON *metaQueue[16];
	cJSON *metaRepeat;
	time_t lastMetaTime;
	unsigned int repeateIndex;
	unsigned char wrQueIdx;
	unsigned char rdQueIdx;
	char *metaString;
	unsigned char metaCorrupt;
	
	unsigned char ext_header[5];
	unsigned char rsp_packet[277];			 	// maximum packet size: 277 bytes.  See below.
	unsigned char rsp_checksum_packet[277];		// checksum packet sent ahead of each new interleaver block if PrivateKey is set, always 277 bytes.
	struct interleaver *interleaver;
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	RSA *rsaPub;
	RSA *rsaPriv;
#endif
	struct sockaddr_in6 bindAddr;
	unsigned char reportToSource;
	struct sockaddr_in6 rrAddr;
	struct sockaddr_in6 rrAddr2;
	int clientSocket;
	int debugSock;				// for debuging packets received
	time_t	lastReport;
	
	char *m_grp;
	unsigned char extCount;
	unsigned int rrPeriod;
	unsigned char FECroots;		// bytes out of 255 that are for coding overhead
	unsigned char flags;		
	unsigned char interleaving; 
	unsigned short colSize;		// interleaver coloumn byte size (network side): 16 to 256 in 16 byte steps. 240 max if RSP_FLAG_RS is set.
								// this is also the number of interleaver rows per block.  The column count is always 255 per block.

	struct rs *network_rs;
	struct rs *audio_rs;
	
    float bw;                   // averaging filter band width multiplier
	float avWrPosition;
    float lastWrPos;
	float rdPosition;
	float wrRate;				// equivelent interleaver rows per second
					
	float columnScaling;		// 0.1 block length averaging constant for columns
	float rowScaling;			// 0.1 block length averaging constant for rows
	
	float FECStat;	// statistics on avarage FEC corrections, Bad Packets and Late packets
	float ErrStat;		
	float BadStat;		
	float DupStat;
	unsigned char playing;		// set automatically if rspSessionPacedReadData or high level rspSessionPlayTask is used to read 
								// out data interleaver data. Otherwise, you will need to set and clear this to indicate the stream
								// state in receiver reports.
	struct timeval lastWrTime;	// the next three variables are used by the high level PlayTask
	struct timeval lastRdTime;
	unsigned int timeout;
};

// handy for use in a relay server or a source streamer
// note: meta must be released (using cJSON_free() function) when done.
struct recvrRecord{
	struct	sockaddr_in6 apparentAddress;
	struct	sockaddr_in6 statedAddress;
	char	*m_grp;
	cJSON	*meta;
	char	*via;					// string identifying the relay server with report was forwarded from. otherwise, null
	unsigned char relay;
	unsigned char relay_cluster;
	char	start_stop_request;		// >0 start request, <0 stop request
	float	FECStat;	
	float	ErrStat;		
	float	BadStat;		
	float	DupStat;
	float	BalStat;
	unsigned char status;
	time_t	lastHeard;
};

// Interleaver definisions 

struct interleaver {
	unsigned short rows;       
	unsigned short columns;  
	unsigned char ratio;
	unsigned char *storage;
	unsigned char *col_checksums; 
	unsigned char *col_erasures;    
	unsigned short rowIdx;
	unsigned char rowBlock;
	unsigned short colIdx;
	unsigned char colBlock;
	int rwBalance;
};

#if defined(__cplusplus)
extern "C"
{
#endif
	
	
//extern struct rspSession *debugSession;
	
// handy functions
void appendstr(char **string, const char *cStr);	
void appendchr(char **string, char chr);
ssize_t rspSendto(int socket, const void *data, size_t size, int flags, const struct sockaddr *addr);
unsigned int ELFHash(unsigned int hash, char* str, unsigned int len);
	
// rsp configuration functions
float rspVersion(const char **vStr);	
struct rspSession *rspSessionNew(const char *clientName);
cJSON *rspSessionReadConfigFile(FILE *fd);
unsigned char rspSessionConfigNextJSON(struct rspSession *session, cJSON **rspObjHandle);
unsigned char rspSessionInit(struct rspSession *session);
void rspSessionClear(struct rspSession *session, unsigned char close_net);
void rspSessionFree(struct rspSession *session);
unsigned char rspSessionNextNetworkSetup(struct rspSession *session, unsigned int nwTimeout, char *bindTo);
unsigned char rspSessionNetworkSetup(cJSON *group, struct rspSession *session, unsigned int nwTimeout, char *bindTo);
void rspSessionClusterSetup(struct rspSession *session, cJSON *relayCluster);
		
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
// public/private key functions for authentication packets
unsigned char rspSessionSetPubKeyString(struct rspSession *session, char *key);
unsigned char rspSessionSetPrivKeyFile(struct rspSession *session, FILE *fp, const char * passwd);
#endif
    
// check packet for format information to initialize session.
unsigned char rspSessionFormatDiscover(struct rspSession *session, unsigned int size);

// interleaver column (packet data) read and write
unsigned char rspSessionWritePacket(struct rspSession *session, unsigned int *size, struct timeval *lastTime);
unsigned int rspSessionReadPacket(struct rspSession *session, unsigned char **packet, unsigned char *data);
	
// interleaver row (decoded stream data) read and write
unsigned char rspSessionWriteData(struct rspSession *session, unsigned char *data, unsigned int size);
unsigned char *rspSessionPacedReadData(struct rspSession *session, unsigned int *size, struct timeval *lastTime);
unsigned char *rspSessionReadData(struct rspSession *session, unsigned int *size, float *period, unsigned char beyond);

// interleaver read and write possition functions
float calculateWriteLocation(struct rspSession *session, unsigned char col, unsigned char block);
void updateWriteLocation(struct rspSession *session, float pos, unsigned char reset);
void updateReadLocation(struct rspSession *session, unsigned char row, unsigned char block, unsigned char reset);
void resetReadPosition(struct rspSession *session, float writePos);
float rspSessionGetReadOffsetFromWritePos(struct rspSession *session, float wrPos);
float rspSessionGetBalance(struct rspSession *session);
	
// metadata stream function
void rspSessionQueueMetadata(struct rspSession *session, cJSON *meta, cJSON *excludeList);
void rspSessionExpiredMetaCheck(struct rspSession *session);
cJSON *rspSessionNextMetadata(struct rspSession *session);
char *rspSessionNextMetaStr(struct rspSession *session);

// high level functions
void rspSessionCheckStatusTime(struct rspSession *session);
int rspSessionNetworkRead(struct rspSession *session, unsigned char noBlock);
unsigned char rspSessionFillTask(struct rspSession *session, char** msg, struct timeval *lastRxTime);
unsigned char *rspSessionPlayTaskPull(struct rspSession *session, cJSON **meta, int *size, unsigned char beyond);
int rspSessionPlayTaskPush(struct rspSession *session, char** msg, cJSON **meta, unsigned char **data, unsigned char rebuffer, float rb_threshold);
unsigned char rspPacketRecvrRequestSend(struct rspSession *session, struct sockaddr_in6 *addr, unsigned char start);

// base functions (used by session functions)
unsigned short rspPacketInit(unsigned char *packet, unsigned char flags, unsigned short payload_size, unsigned char *netRoots);
unsigned char rspPacketHandle(unsigned char *packet, unsigned short size, unsigned char *flags, unsigned short *payload_size, unsigned char *col, unsigned char *block, unsigned char *netRoots);
#if !TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
unsigned short rspPacketSignedChecksumsSet(unsigned char *packet, unsigned char *check_sums, unsigned char block, RSA *rsa, unsigned int *crc_table);
unsigned char rspPacketReadHeader(unsigned char *packet, unsigned short size, unsigned char *flags, unsigned short *payload_size, unsigned char *col, unsigned char *block, struct rs *rs_session, RSA *rsa, unsigned int *crc_table);
unsigned short rspPacketResetSet(unsigned char *packet, struct rs *rs_session, RSA *rsa, unsigned int *crc_table);
#else
unsigned char rspPacketReadHeader(unsigned char *packet, unsigned short size, unsigned char *flags, unsigned short *payload_size, unsigned char *col,unsigned char *block, struct rs *rs_session, void *rsa, unsigned int *crc_table);
unsigned short rspPacketResetSet(unsigned char *packet, struct rs *rs_session, void *rsa, unsigned int *crc_table);
#endif
unsigned short rspPacketPayloadSet(unsigned char *packet, unsigned char *payload, struct rs *rs_session, unsigned char column, unsigned char block, unsigned char ex_fec, unsigned char ex_il, unsigned int *crc_table);
// payload buffer size must match the payload_size previously set for the packet with rspPacketInit
// this function will also calculate and set the CRC and RS encode the packet if those flags were set with rspPacketInit
unsigned char rspPacketRecvrReportRequestGet(unsigned char *packet, struct sockaddr_in6 *fromAddress, struct recvrRecord *recvrRecord);
void rspRecvrReportFree(struct recvrRecord *recvrRecord);
unsigned short rspPacketRecvrReportSet(struct rspSession *session, unsigned char force_relay);

// Interleaver primative functions
struct interleaver *il_init(unsigned short row_n, unsigned short col_n, unsigned char ratio);

void il_free(struct interleaver *il);
void il_reset(struct interleaver *il);
void il_clearBlock(struct interleaver *il, unsigned char block);

unsigned char il_rowColumnOverlap(struct interleaver *il);

unsigned char* il_getRow(struct interleaver *il, unsigned short row, unsigned char block);
unsigned char* il_getCurRow(struct interleaver *il);
unsigned char il_nextRow(struct interleaver *il);

void il_copyColumn(struct interleaver *il, unsigned char *data, unsigned short col, unsigned char block);
void il_copyCurColumn(struct interleaver *il, unsigned char *data);
unsigned char il_writeColumn(struct interleaver *il, unsigned char *data, unsigned short col, unsigned char block, unsigned char extended);
void il_writeCurColumn(struct interleaver *il, unsigned char *data);
unsigned char il_nextColumn(struct interleaver *il);
unsigned char il_incColumn(struct interleaver *il, unsigned short *col, unsigned char *blk);

void il_updateBlockChecksums(struct interleaver *il, unsigned char block);
void il_receiverChecksums(struct interleaver *il, unsigned char block, unsigned char *checksums);
unsigned char *il_getChecksums(struct interleaver *il, unsigned char block);
unsigned char il_getChecksum(struct interleaver *il, unsigned short col, unsigned char block);
unsigned char il_getChecksumValid(struct interleaver *il, unsigned char block);

unsigned char il_getBlockErasures(struct interleaver *il, unsigned char block, unsigned char *erasures);
unsigned char il_getBlockFilledCount(struct interleaver *il, unsigned char block);

#if defined(__cplusplus)
}
#endif

#endif
