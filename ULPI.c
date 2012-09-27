#include "TLAPlugin.h"
#include "ULPI.h"
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>
#include <windows.h>
#include <time.h>
#include <errno.h>
#include <sys/param.h>

#define    MIN(a,b)    (((a)<(b))?(a):(b))

static const unsigned short crc16tab[256]= {
	0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
	0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
	0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
	0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
	0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
	0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
	0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
	0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
	0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
	0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
	0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
	0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
	0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
	0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
	0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
	0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
	0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
	0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
	0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
	0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
	0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
	0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
	0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
	0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
	0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
	0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
	0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
	0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
	0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
	0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
	0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
	0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

static FILE *logfile = NULL;
static int idsel_values[16] = { 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

const char *modeinfo_names[MODEINFO_MAX] = {
	"MAX_BUS",
	"MAX_GROUP",
	"MAX_MODE",
	"3",
	"GETNAME"
};

static const char *linestates[] = {
	"SE0 / squelch",
	"J / !squelch",
	"K",
	"SE1"
};

#define ULPI_EVENT(_x) (((_x) >> 4) & 3)

static const char *rxevents[] = {
	"NONE",
	"RXACTIVE",
	"RXACTIVE, RXERROR",
	"HOSTDISCONNECT"
};

#define ULPI_DIR 0x01
#define ULPI_NXT 0x02
#define ULPI_STP 0x04
#define ULPI_RST 0x08

typedef enum {
	USB_PID_XXX=0xf0,
	USB_PID_OUT=0xe1,
	USB_PID_ACK=0xd2,
	USB_PID_DATA0=0xc3,
	USB_PID_PING=0xb4,
	USB_PID_SOF=0xa5,
	USB_PID_NYET=0x96,
	USB_PID_DATA2=0x87,
	USB_PID_SPLIT=0x78,
	USB_PID_IN=0x69,
	USB_PID_NAK=0x5a,
	USB_PID_DATA1=0x4b,
	USB_PID_PRE=0x3c,
	USB_PID_SETUP=0x2d,
	USB_PID_STALL=0x1e,
	USB_PID_MDATA=0x0f,
} usb_pid_t;

#define ULPI_EVENT_NONE 0
#define ULPI_EVENT_RXACTIVE 1
#define ULPI_EVENT_RXERROR 2
#define ULPI_EVENT_HOSTDISCONNECT 3

typedef enum {
	ULPI_GROUP_DATA=0,
	ULPI_GROUP_CTRL,
	ULPI_GROUP_DECODED,
} group_id_t;

#define GROUP_CYCLE_TYPE 2

#define GROUP_CYCLE_TYPE_RESET 1
#define GROUP_CYCLE_TYPE_PID 2
#define GROUP_CYCLE_TYPE_DATA 3

struct groupinfo groupinfo[] = {
	GROUP("DATA", GROUP_TYPE_INPUT, 8, 0, NULL),
	GROUP("CTRL", GROUP_TYPE_INPUT, 4, 0, NULL),
	GROUP("Cycle Type", GROUP_TYPE_FAKE_GROUP, 8, 8, "ULPI_Cycle.tsf"),
	GROUP("Decoded cycle", GROUP_TYPE_MNEMONIC, SEQUENCE_TEXT_WIDTH, SEQUENCE_TEXT_WIDTH, NULL)
};

struct businfo businfo[] = { { .groupcount = ARRAY_SIZE(groupinfo) } };

char *onoff[] = { "Off", "On", NULL, NULL };

struct modeinfo modeinfo[] = { { "Show SOF packets", onoff, 1, 0 },
                               { "Show buffers", onoff, 2, 0 } };

struct stringmodevalues stringmodevalues[] = { { "All cycles", DISPLAY_ATTRIBUTE_ALL },
                                               { "Decoded cycles", DISPLAY_ATTRIBUTE_DECODED },
                                               { "Highlevel", DISPLAY_ATTRIBUTE_HIGHLEVEL },
                                               { "Aborted cycles", DISPLAY_ATTRIBUTE_ABORTED } };

struct stringmodename stringmodename = { ARRAY_SIZE(stringmodevalues), "Show:", stringmodevalues, NULL };


static void LogDebug(struct pctx *pctx, int level, const char *fmt, ...)
{
        char buf[4096];

        if (!logfile)
                logfile = fopen("c:\\Users\\svens\\tlatrace.txt", "w+");

        if (!logfile)
                return;

        if (level >= 6)
                return;

	va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        fprintf(logfile, "%s", buf);
        fflush(logfile);
}

int ParseFinish(struct pctx *pctx)
{
	LogDebug(pctx, 8, "%s(%p)\n", __FUNCTION__, pctx);
	if (logfile)
		fclose(logfile);
	logfile = NULL;
	pctx->func.rda_free(pctx);
	return 0;
}

static struct sequence *get_sequence(struct pctx *pctx)
{
        struct sequence *ret;
        unsigned int i;

        if (!(ret = pctx->func.rda_calloc(1, sizeof(struct sequence)))) {
                LogDebug(pctx, 6, "calloc failed\n");
                return NULL;
        }

        ret->textp = ret->text;
        ret->group_values = calloc(ARRAY_SIZE(groupinfo), sizeof(struct group_value));
        for(i = 0; i < ARRAY_SIZE(groupinfo); i++)
                ret->group_values[i].mask = 0xf;
        return ret;
}

static uint8_t ulpi_get_ctrl_group(struct pctx *pctx, int seq)
{
	return pctx->func.LAGroupValue(pctx->lactx, seq, ULPI_GROUP_CTRL);
}

static uint8_t ulpi_get_data_group(struct pctx *pctx, int seq)
{
	return pctx->func.LAGroupValue(pctx->lactx, seq, ULPI_GROUP_DATA);
}

static int ulpi_is_rxcmd(uint8_t ctrl)
{
	return (!(ctrl & ULPI_NXT) && ctrl & ULPI_DIR);
}

static int ulpi_is_turnaround(struct pctx *pctx, int seq, uint8_t ctrl)
{
	uint8_t ctrl2;

	seq = pctx->func.LAFindSeq(pctx->lactx, seq, -1, -1);
	
	if (seq < 0)
		return 0;

	ctrl2 = ulpi_get_ctrl_group(pctx, seq);

	return ((ctrl & ULPI_DIR) != (ctrl2 & ULPI_DIR));

}

static int ulpi_is_rxdata(uint8_t ctrl)
{
	return ((ctrl & ULPI_NXT) &&
		(ctrl & ULPI_DIR));
}

static int ulpi_find_start_of_packet(struct pctx *pctx, int seq)
{
	uint8_t ctrl, data;
	uint8_t previous_rxcmd = ulpi_get_ctrl_group(pctx, seq);
	uint8_t previous_data = ulpi_get_data_group(pctx, seq);
	int seenactive = -1, seq2;

	LogDebug(pctx, 8, "%s: %d\n", __FUNCTION__, seq);

	if (!ulpi_is_rxcmd(previous_rxcmd)) {
		LogDebug(pctx, 8, "%s: not rxcmd\n", __FUNCTION__);
		return -1;
	}

	if (ULPI_EVENT(previous_data) != ULPI_EVENT_NONE) {
		LogDebug(pctx, 8, "%s: not none event\n", __FUNCTION__);
		return -1;
	}

	for(;;) {
		seq = pctx->func.LAFindSeq(pctx->lactx, seq, -1, -1);
		if (seq < 0)
			break;

		data = ulpi_get_data_group(pctx, seq);
		ctrl = ulpi_get_ctrl_group(pctx, seq);

		if ((ctrl & ULPI_NXT) &&
		    (ctrl & ULPI_DIR)) {
			seq2 = pctx->func.LAFindSeq(pctx->lactx, seq, -1, -1);
			if (seq2 >= 0) {
				ctrl = ulpi_get_ctrl_group(pctx, seq2);
				if (!(ctrl & ULPI_NXT) &&
				    !(ctrl & ULPI_DIR))
					seenactive = pctx->func.LAFindSeq(pctx->lactx, seq, 1, -1);
				continue;
			}
		}

		if (!ulpi_is_rxcmd(ctrl))
			continue;

		if (ulpi_is_turnaround(pctx, seq, ctrl))
			continue;

		switch(ULPI_EVENT(data)) {
		case ULPI_EVENT_NONE:
			return seenactive;

		case ULPI_EVENT_RXACTIVE:
			seenactive = pctx->func.LAFindSeq(pctx->lactx, seq, 1, -1);
			break;

		case ULPI_EVENT_RXERROR:
			break;

		case  ULPI_EVENT_HOSTDISCONNECT:
			break;
		}
	}
	return seq;
}

static const char *pidnames[] = {
	"XXX",
	"OUT",
	"ACK",
	"DATA0",
	"PING",
	"SOF",
	"NYET",
	"DATA2",
	"SPLIT",
	"IN",
	"NAK",
	"DATA1",
	"PRE",
	"SETUP",
	"STALL",
	"MDATA"
};

static struct sequence *attach_sequence(struct sequence *in, struct sequence *seq)
{
	struct sequence *firstseq = NULL;

	if (!in)
		return seq;

	firstseq = in;

	while(in->next)
		in = in->next;

	in->next = seq;
	return firstseq;
}

static struct sequence *dump_data_to_sequence(struct pctx *pctx, uint8_t *bytes,
					      int bytecnt)
{
	struct sequence *firstseq = NULL, *seqinfo;
	int i, j;

	for(i = 0; i < bytecnt; i+= 16) {
		seqinfo = get_sequence(pctx);
		seqinfo->flags = DISPLAY_ATTRIBUTE_HIGHLEVEL;
		LogDebug(pctx, 5, "i: %d\n", i);
		for(j = 0; j < MIN(16, bytecnt); j++) {
			LogDebug(pctx, 5, "j: %d\n", j);
			sprintf(seqinfo->textp + j * 3, "%02X ", bytes[j+i]);
		}
		bytecnt -= j;
		firstseq = attach_sequence(firstseq, seqinfo);
	}
	return firstseq;
}

#define SHIFT (sizeof(uint32_t) * 8 - 1)

static uint32_t crc5(uint32_t data, unsigned int bitcnt)
{
	const uint32_t poly5 = 5 << SHIFT;
	uint32_t crc5 = 0x1f << SHIFT;


	data <<= sizeof(uint32_t) * 8 - bitcnt;

	while(bitcnt--) {
		if ((data ^ crc5) & (1 << SHIFT)) {
			crc5 <<= 1;
			crc5 ^= poly5;
		} else {
			crc5 <<= 1;
		}
		data <<= 1;
	}

	crc5 >>= (sizeof(uint32_t) * 8 - 5);
	crc5 ^= 0x1f;
	return crc5;
}

static int crc16(void *buf, int len)
{
	uint16_t crc = 0;
	while(len--)
		crc = (crc << 8) ^ crc16tab[((crc >> 8) ^ *(uint8_t *)buf++) & 0xff];
	return crc;
}

static struct sequence *ulpi_decode_packet(struct pctx *pctx, int startseq)
{
	struct sequence *firstseq = NULL, *seqinfo = NULL;
	uint16_t data16 = 0, tmp;
	uint8_t ctrl, data, pid = 0, endp;
	int bytecnt, seq;
	uint8_t bytes[1024];

	for(bytecnt = 0, seq = startseq; seq > 0;
	    seq = pctx->func.LAFindSeq(pctx->lactx, seq, 1, -1)) {

		ctrl = ulpi_get_ctrl_group(pctx, seq);
		if (ulpi_is_rxcmd(ctrl)) {

			data = ulpi_get_data_group(pctx, seq);
			if (ULPI_EVENT(data) == ULPI_EVENT_RXACTIVE)
				continue;

			if (bytecnt > 0 && !pctx->show_sof && pid == USB_PID_SOF)
				return NULL;

			seqinfo = get_sequence(pctx);
			seqinfo->flags = DISPLAY_ATTRIBUTE_HIGHLEVEL;

			if (bytecnt == 0) {
				sprintf(seqinfo->textp, "ERROR: NO PID");
				seqinfo->flags = DISPLAY_ATTRIBUTE_ABORTED;
				return attach_sequence(firstseq, seqinfo);
			}

			if (((pid >> 4) & 0x0f) != (~pid & 0x0f)) {
				sprintf(seqinfo->textp, "ERROR: INVALID PID 0x%02X", pid);
				seqinfo->flags = DISPLAY_ATTRIBUTE_ABORTED;
				return attach_sequence(firstseq, seqinfo);
			}

			switch(pid) {
			case USB_PID_ACK:
			case USB_PID_NAK:
			case USB_PID_STALL:
			case USB_PID_NYET:
				/* 1 byte pids */
				sprintf(seqinfo->textp, "PID %s", pidnames[pid & 0x0f]);
				break;

			case USB_PID_DATA0:
			case USB_PID_DATA1:
			case USB_PID_DATA2:
			case USB_PID_MDATA:
				sprintf(seqinfo->textp, "PID %s, %d bytes",
					pidnames[pid & 0x0f], bytecnt-3);
				if (bytecnt > 3 && pctx->show_buffers)
					seqinfo->next = dump_data_to_sequence(pctx, bytes + 1, bytecnt-3);
				if (bytecnt > 3) {
					LogDebug(pctx, 5,"CRC16: %04X, should be %02X%02X\n", crc16(bytes+1, bytecnt - 3),
						 bytes[bytecnt-2], bytes[bytecnt-1]);
				}
				break;
				
			case USB_PID_SETUP:
			case USB_PID_OUT:
			case USB_PID_IN:
			case USB_PID_PING:
				if (bytecnt >= 2) {
					sprintf(seqinfo->textp, "PID %s, Address %d, EP %d, CRC5 %d",
						pidnames[pid & 0x0f], (data16 >> 9) & 0x8f,
						(data >> 5) & 0x0f, data & 0x1f);
				} else {
					sprintf(seqinfo->textp, "PID %s, Short packet (%d bytes)",
						pidnames[pid & 0x0f], bytecnt);
					seqinfo->flags = DISPLAY_ATTRIBUTE_ABORTED;
				}
				break;

			case USB_PID_SOF:		

				tmp = (data16 >> 8) & 0xff;
				tmp |= (data16 & 0xff) << 8;
				if (bytecnt >= 2) {
					sprintf(seqinfo->textp, "PID %s, FRAME# %04x, CRC5 0x%02x, %02x",
						pidnames[pid & 0x0f], tmp & 0x7ff, (tmp >> 10) & 0x1f, crc5(tmp & 0x7ff, 11));
				} else {
					sprintf(seqinfo->textp, "PID %s, Short packet (%d bytes)",
						pidnames[pid & 0x0f], bytecnt);
					seqinfo->flags = DISPLAY_ATTRIBUTE_ABORTED;
				}
				break;
				
			default:
				sprintf(seqinfo->textp, "PID %x unknown", pid);
				seqinfo->flags = DISPLAY_ATTRIBUTE_ABORTED;
				break;
			}

			return attach_sequence(firstseq, seqinfo);			
		}

		if (bytecnt == 0) {
			pid = ulpi_get_data_group(pctx, seq);
			data16 = 0;
		} else if(bytecnt == 1) {
			data16 |= (ulpi_get_data_group(pctx, seq) << 8);
		} else if (bytecnt == 2) {
			data16 |= ulpi_get_data_group(pctx, seq);
		}
		bytes[bytecnt] = ulpi_get_data_group(pctx, seq);
		bytecnt++;
		
	}
 	return firstseq;
}

struct sequence *ulpi_detect_reset(struct pctx *pctx, int seq)
{
	struct sequence *seqinfo;
	uint64_t ts, ts2, ts1;
	uint8_t ctrl;
	int nextseq;
	char buf[128];

	nextseq = seq;
	for(;;) {
		nextseq = pctx->func.LAFindSeq(pctx->lactx, nextseq, 1, -1);

		if (nextseq < 0)
			return 0;

		ctrl = ulpi_get_ctrl_group(pctx, nextseq);
		if (!ulpi_is_rxcmd(ctrl))
			continue;

		if ((ctrl & 3) != 0)
			break;
	}

	pctx->func.LATimeStamp_ps(pctx->lactx, nextseq, &ts1);	
	pctx->func.LATimeStamp_ps(pctx->lactx, seq, &ts2);

	ts = ts1 - ts2;
	if (ts < (3LL * 1000LL * 1000LL * 1000LL))
		return NULL;
		
	pctx->func.LATimestamp_ps_ToText(pctx->lactx, &ts, buf, sizeof(buf));
	seqinfo = get_sequence(pctx);
	seqinfo->flags = DISPLAY_ATTRIBUTE_ABORTED;
	sprintf(seqinfo->textp, "USB RESET [duration: %s]", buf);
	return seqinfo;
}

struct sequence *ParseSeq(struct pctx *pctx, int seq)
{
	struct sequence *seqinfo = NULL;
	uint8_t data, ctrl, pctrl, linestate, rxevent;
	int startseq, prevseq, minseq, maxseq;


        LogDebug(pctx, 8, "ParseSeq %d\n", seq);

	if (!pctx) {
		LogDebug(pctx, 9, "pctx NULL\n");
		return NULL;
	}

        pctx->displayattribute = pctx->func.LAInfo(pctx->lactx, TLA_INFO_DISPLAY_ATTRIBUTE, -1);

	prevseq = pctx->func.LAFindSeq(pctx->lactx, seq, -1, -1);
	if (prevseq < 0)
		return NULL;

	pctrl = pctx->func.LAGroupValue(pctx->lactx, prevseq, 1);
	ctrl = pctx->func.LAGroupValue(pctx->lactx, seq, 1);
	data = pctx->func.LAGroupValue(pctx->lactx, seq, 0);

	if ((ctrl & (ULPI_NXT|ULPI_DIR)) == ULPI_DIR &&
	    ((data & 3) == 0) &&
	    (seqinfo = ulpi_detect_reset(pctx, seq)))
		return seqinfo;

	if (!(pctx->lastctrl & ULPI_NXT)) {
		if (pctx->lastdata == data &&
		    pctx->lastctrl == ctrl)
			return NULL;
	}

	pctx->lastctrl = ctrl;
	pctx->lastdata = data;

	if ((pctrl & ULPI_DIR) != (ctrl & ULPI_DIR)) {
		seqinfo = get_sequence(pctx);	
		seqinfo->flags = DISPLAY_ATTRIBUTE_ALL;
		sprintf(seqinfo->textp, "TURNAROUND");
		return seqinfo;
		
	}

	if (!(ctrl & ULPI_DIR)) {
		seqinfo = get_sequence(pctx);	
		seqinfo->flags = DISPLAY_ATTRIBUTE_DECODED;
		if (!(ctrl & ULPI_NXT)) {
			switch((data >> 6) & 3) {
			case 0:
				seqinfo->flags = DISPLAY_ATTRIBUTE_ALL;
				sprintf(seqinfo->textp, "NOP COMMAND");
				break;
			case 1:
				sprintf(seqinfo->textp, "TRANSMIT COMMAND");
				break;
			case 2:
				sprintf(seqinfo->textp, "REGWRITE COMMAND");
				break;
			case 3:
				sprintf(seqinfo->textp, "REGREAD COMMAND");
				break;
			}
		} else {
			sprintf(seqinfo->textp, "COMMAND DATA");
		}
		return seqinfo;		
	}

	if ((ctrl & (ULPI_DIR|ULPI_NXT)) == ULPI_DIR) {
		seqinfo = get_sequence(pctx);	
		seqinfo->flags = DISPLAY_ATTRIBUTE_ALL;

		linestate = data & 3;
		rxevent = (data >> 4) & 3;

		if (rxevent == ULPI_EVENT_NONE) {
			startseq = ulpi_find_start_of_packet(pctx, seq);
			if (startseq > 0) {
				seqinfo->next = ulpi_decode_packet(pctx, startseq);
			}
		}
		sprintf(seqinfo->textp, "RXCMD, linestate %s, event %s",
			linestates[linestate], rxevents[rxevent]);
		return seqinfo;
	}

	if ((ctrl & ULPI_DIR) && (ctrl & ULPI_NXT)) {
		seqinfo = get_sequence(pctx);	
		seqinfo->flags = DISPLAY_ATTRIBUTE_DECODED;
		sprintf(seqinfo->textp, "USB RX byte");
		return seqinfo;
	}
	return NULL;
}

int ParseMarkNext(struct pctx *pctx, int seq, int a3)
{
	LogDebug(pctx, 9, "%s: sequence %d, a3 %d\n", __FUNCTION__, seq, a3);
	return 0;
}

int ParseMarkSet(struct pctx *pctx, int seq, int a3)
{
	LogDebug(pctx, 9, "%s\n", __FUNCTION__);
	return 0;
}

int ParseMarkGet(struct pctx *pctx, int seq)
{
	LogDebug(pctx, 9, "%s: sequence %d\n", __FUNCTION__, seq);
	return 0;
}


int ParseMarkMenu(struct pctx *pctx, int seq, char ***names, char **entries, char **val)
{
        return 0;
}

int ParseInfo(struct pctx *pctx, unsigned int request)
{
	LogDebug(pctx, 8, "%s: %s\n", __FUNCTION__,
                 request > ARRAY_SIZE(modeinfo_names) ? "invalid" : modeinfo_names[request]);

	switch(request) {
        case MODEINFO_MAX_BUS:
                return ARRAY_SIZE(businfo);
        case MODEINFO_MAX_GROUP:
                return ARRAY_SIZE(groupinfo);
        case MODEINFO_GETNAME:
                return (int)"ULPI";
        case 3:
                return 1;
        case MODEINFO_MAX_MODE:
                return ARRAY_SIZE(modeinfo);
        default:
                LogDebug(pctx, 6, "%s: invalid request: %d\n", __FUNCTION__, request);
                return 0;
	}
	return 0;
}

int ParseExtInfo_(struct pctx *pctx, int request, void *out)
{
	LogDebug(pctx, 8, "%s: %d\n", __FUNCTION__, request);
        switch(request) {
        case 0:
                *(struct stringmodename **)out = &stringmodename;
                return 1;
        case 1:
        case 2:
/*        case 3:
        case 4:
        case 5:*/
        case 7:
                *(int *)out = 1;
                return 1;
		/*	case 8: Subdisasm Functable size */

        default:
                return 0;

        }
}

struct businfo *ParseBusInfo(struct pctx *pctx, uint16_t bus)
{
	LogDebug(pctx, 8, "%s: %08x\n", __FUNCTION__, bus);

	if (bus >= ARRAY_SIZE(businfo))
		return NULL;
	return businfo+bus;
}

struct groupinfo *ParseGroupInfo(struct pctx *pctx, uint16_t group)
{
	LogDebug(pctx, 8, "%s: %08x\n", __FUNCTION__, group);

	if (group > ARRAY_SIZE(groupinfo))
                return NULL;
	return groupinfo+group;
}

struct modeinfo *ParseModeInfo(struct pctx *pctx, uint16_t mode)
{
	LogDebug(pctx, 8, "%s: %d\n", __FUNCTION__, mode);
	if (mode > ARRAY_SIZE(modeinfo))
                return NULL;
	return modeinfo+mode;
}

int ParseModeGetPut(struct pctx *pctx, int16_t mode, int value, int request)
{
        int firstseq, lastseq;
        if (mode >= 0) {
                LogDebug(pctx, 5, "%s: %d (%s), %d (%s)\n", __FUNCTION__,
                         request, modeinfo[mode].name, value, onoff[value]);

                firstseq = pctx->func.LAInfo(pctx->lactx, TLA_INFO_FIRST_SEQUENCE, -1);
                lastseq = pctx->func.LAInfo(pctx->lactx, TLA_INFO_LAST_SEQUENCE, -1);
                pctx->func.LAInvalidate(pctx->lactx, -1, firstseq, lastseq);

                switch(mode) {
                case 0:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_sof = value;
                        value = pctx->show_sof;
                        break;
                case 1:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_buffers = value;
                        value = pctx->show_buffers;
                        break;
                default:
                        break;
                }
        }
	return value;
}


int ParseStringModeGetPut_(struct pctx *pctx, int mode, int value, int request)
{
	LogDebug(pctx, 8, "%s: %d (%s), %d (%s)\n", __FUNCTION__,
                 request, modeinfo[mode].name, value, onoff[value]);
	return value;
}

struct pctx *ParseReinit(struct pctx *pctx, struct lactx *lactx, struct lafunc *func)
{
	struct pctx *ret = NULL;

        LogDebug(ret, 8, "%s(%p, %p, %p)\n", __FUNCTION__, pctx, lactx, func);

	if (pctx)
                return pctx;

	if (!(ret = func->rda_calloc(1, sizeof(struct pctx)))) {
		func->LAError(0, 9, "Out of Memory");
		return NULL;
	}

	ret->lactx = lactx;
        memcpy(&ret->func, func, sizeof(struct lafunc));
	return ret;
}

int ParseDisasmReinit(struct pctx *pctx, int request)
{
        struct seqlog *seqlog;

	LogDebug(pctx, 8, "%s(%p, %d)\n", __FUNCTION__, pctx, request);
        return 1;
}
