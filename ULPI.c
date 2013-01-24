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
#define ULPI_RXCMDVALID 0x08
#define ULPI_PID 0x10
#define ULPI_DATAVALID 0x20

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
	GROUP("PID", GROUP_TYPE_FAKE_GROUP, 4, 4, "PID.tsf"),
	GROUP("ADDR", GROUP_TYPE_FAKE_GROUP, 7, 7, NULL),
	GROUP("EP", GROUP_TYPE_FAKE_GROUP, 4, 4, NULL),
	GROUP("DATA size", GROUP_TYPE_FAKE_GROUP, 32, 32, NULL),
	GROUP("Decoded cycle", GROUP_TYPE_MNEMONIC, SEQUENCE_TEXT_WIDTH, SEQUENCE_TEXT_WIDTH, NULL)
};

#define GROUP_PID 2
#define GROUP_ADDR 3
#define GROUP_EP 4
#define GROUP_DATA_SIZE 5

struct businfo businfo[] = { { .groupcount = ARRAY_SIZE(groupinfo) } };

char *onoff[] = { "Off", "On", NULL, NULL };

#define SHOW_SOF 0
#define SHOW_IN 1
#define SHOW_OUT 2
#define SHOW_SETUP 3
#define SHOW_NAK 4
#define SHOW_ACK 5
#define SHOW_NYET 6
#define SHOW_DATA 7
#define SHOW_STALL 8
#define SHOW_PING 9
#define SHOW_BUF 10

struct modeinfo modeinfo[] = { { "Show SOF packets", onoff, SHOW_SOF, 0 },
			       { "Show IN packets", onoff, SHOW_IN, 0 },
			       { "Show OUT packets", onoff, SHOW_OUT, 0 },
			       { "Show SETUP packets", onoff, SHOW_SETUP, 0 },
			       { "Show NAK packets", onoff, SHOW_NAK, 0 },
			       { "Show ACK packets", onoff, SHOW_ACK, 0 },
			       { "Show NYET packets", onoff, SHOW_NYET, 0 },
			       { "Show DATA packets", onoff, SHOW_DATA, 0 },
			       { "Show PING packets", onoff, SHOW_PING, 0 },
			       { "Show STALL packets", onoff, SHOW_STALL, 0 },
                               { "Show buffers", onoff, SHOW_BUF, 0 } };

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

static void dump_data_to_sequence(struct pctx *pctx,
				  struct sequence **firstseq, uint8_t *bytes,
				  int bytecnt)
{
	struct sequence *seqinfo;
	int i, j;
	uint8_t c;

	for(i = 0; i < bytecnt; i+= 16) {
		seqinfo = get_sequence(pctx);
		seqinfo->flags = DISPLAY_ATTRIBUTE_DECODED;
		memset(seqinfo->textp, ' ', 64);
		sprintf(seqinfo->textp, "0x%04X: ", i);
		for(j = 0; j < 16; j++) {
			if (i + j >= bytecnt)
				break;
			c = bytes[j+i];
			sprintf(seqinfo->textp + 8 + j * 3, "%02X ", c);
			seqinfo->textp[8 + j * 3 + 3] = ' ';
			if (c > 0x20 && c < 0x7f)
				sprintf(seqinfo->textp + 57 + j, "%c", c);
			else
				sprintf(seqinfo->textp + 57 + j, ".");
		}
		*firstseq = attach_sequence(*firstseq, seqinfo);
	}
}

#define SHIFT (sizeof(uint32_t) * 8 - 1)

static void sequence_printf(struct pctx *pctx, int flags,
			    struct sequence **seq, const char *fmt, ...)
{
	struct sequence *firstseq, *seqinfo = get_sequence(pctx);
	va_list va;

	
	va_start(va, fmt);
	vsnprintf(seqinfo->textp, SEQUENCE_TEXT_WIDTH, fmt, va);
	va_end(va);

	seqinfo->flags = flags;
	firstseq = attach_sequence(*seq, seqinfo);
	*seq = firstseq;
}

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

static int get_usb_packet(struct pctx *pctx, int startseq, uint8_t *buf, int maxlen)
{
	int nextseq, seq, len = 0;
	uint32_t ctrl;

	seq = startseq;

	for(;;) {
		nextseq = pctx->func.LAFindSeq(pctx->lactx, seq, 1, -1);
		if (nextseq == -1)
			break;
		seq = nextseq;
		ctrl = pctx->func.LAGroupValue(pctx->lactx, seq, 1);
		if (ctrl & ULPI_PID)
			break;

		if (!(ctrl & ULPI_DATAVALID))
			continue;

		*buf++ = pctx->func.LAGroupValue(pctx->lactx, seq, 0);
		if (len++ == maxlen)
			break;
	}
	return len;
}

uint8_t get_previous_pid(struct pctx *pctx, int startseq)
{
	int nextseq, seq = startseq, seq2;
	uint32_t data, ctrl;
	for(;;) {
		nextseq = pctx->func.LAFindSeq(pctx->lactx, seq, -1, -1);
		LogDebug(pctx, 8, "nextseq: %d\n", nextseq);
		if (nextseq == -1)
			break;
		seq = nextseq;
		ctrl = pctx->func.LAGroupValue(pctx->lactx, seq, 1);
		if (!(ctrl & ULPI_PID)) {
			LogDebug(pctx, 8, "%d: no PID\n", nextseq);
			continue;
		}

		if (ctrl & ULPI_DATAVALID) {
			data = pctx->func.LAGroupValue(pctx->lactx, seq, 0);
		} else {
			seq2 = pctx->func.LAFindSeq(pctx->lactx, seq, 1, -1);
			if (seq2 < 0)
				break;
			data = pctx->func.LAGroupValue(pctx->lactx, seq2, 0);
		}
		LogDebug(pctx, 8, "Data: %02X\n", data);
		switch(data) {
		case USB_PID_SETUP:
		case USB_PID_IN:
		case USB_PID_OUT:
			return data;
		default:
			break;
		}
	}
	return 0;
}

static const char *usb_setup_types[] = {
	"Standard",
	"Class",
	"Vendor",
	"Reserved"
};

static const char *usb_setup_recipient(uint8_t val)
{
	switch(val & 0x1f) {
	case 0:
		return "Device";
	case 1:
		return "Interface";
	case 2:
		return "Endpoint";
	case 3:
		return "Other";
	default:
		return "Reserved";
	}
}

static const char *usb_setup_request(uint8_t request)
{
	switch(request) {
	case 0:
		return "GET_STATUS";
	case 1:
		return "CLEAR_FEATURE";
	case 3:
		return "SET_FEATURE";
	case 5:
		return "SET_ADDRESS";
	case 6:
		return "GET_DESCRIPTOR";
	case 7:
		return "SET_DESCRIPTOR";
	case 8:
		return "GET_CONFIGURATION";
	case 9:
		return "SET_CONFIGURATION";
	default:
		return "Unknown request";
	}

}

static void dump_usb_setup_packet(struct pctx *pctx, struct sequence **firstseq,
				  uint8_t *buf, int len, int seq)
{
	uint8_t request = buf[1];
	uint16_t wValue = ((buf[3] << 8) | buf[2]);
	uint16_t wIndex = ((buf[5] << 8) | buf[4]);
	char *description = "Unknown";
	char tmp[64];

	switch(request) {
	case 0: /* GET_STATUS */
		break;
	case 1: /* CLEAR_FEATURE */
	case 3: /* SET_FEATURE */
		switch(wValue) {
		case 0:
			description = "ENDPOINT_HALT (0x00)";
			break;
		case 1:
			description = "DEVICE_REMOTE_WAKEUP (0x01)";
			break;
		case 2:
			description = "TEST_MODE (0x02)";
			break;
		case 3:
			description = "B_HNP_ENABLE (0x03)";
			break;
		case 4:
			description = "A_HNP_SUPPORT (0x04)";
			break;
		case 5:
			description = "A_ALT_HNP_SUPPORT (0x05)";
			break;
		case 6:
			description = "DEBUG (0x06)";
			break;
		default:
			snprintf(tmp, sizeof(tmp), "Unknown Feature %04X", wValue);
			description = tmp;
			break;
		}
		break;
	case 5: /* SET_ADDRESS */
		snprintf(tmp, sizeof(tmp), "%d", wValue);
		description = tmp;
		break;

	case 6: /* GET DESCRIPTOR */
	case 7: /* SET_DESCRIPTOR */
		switch(wValue >> 8) {
		case 1:
			description = tmp;
			snprintf(tmp, sizeof(tmp), "DEVICE %d", wValue & 0xff);;
			break;
		case 2:
			description = tmp;
			snprintf(tmp, sizeof(tmp), "CONFIGURATION %d", wValue & 0xff);;
			break;
		case 3:
			description = tmp;
			snprintf(tmp, sizeof(tmp), "STRING %d", wValue & 0xff);;
			break;
		case 4:
			description = tmp;
			snprintf(tmp, sizeof(tmp), "INTERFACE %d", wValue & 0xff);;
			break;
		case 5:
			description = tmp;
			snprintf(tmp, sizeof(tmp), "ENDPOINT %d", wValue & 0xff);;
			break;
		case 10:
			description = "DEBUG";
			break;
		case 0x21:
			description = "HID";
			break;
		case 0x22:
			description = "REPORT";
			break;
		case 0x23:
			description = "PHYSICAL";
			break;
		case 0x29:
			description = "HUB";
			break;
		default:
			sprintf(tmp, "Unknown descriptor 0x%04X", wValue);
			description = tmp;
			break;
		}
		break;

	case 8: /* GET_CONFIGURATION */
		description = "GET_CONFIGURATION";
		break;
	case 9: /* SET_CONFIGURATION */
		description = tmp;
		snprintf(tmp, sizeof(tmp), "SET_CONFIGURATION %d", wValue & 0xff);;
		break;
	default:
		description = tmp;
		snprintf(tmp, sizeof(tmp), "Unknown bRequest %04x", wValue);;
		break;
	}
	sequence_printf(pctx, DISPLAY_ATTRIBUTE_DECODED,
			firstseq, "%s %s %c->%c %s %s",
			usb_setup_types[(buf[0] >> 5) & 3],
			usb_setup_recipient(buf[0]),
			buf[0] & 0x80 ? 'D' : 'H',
			buf[0] & 0x80 ? 'H' : 'D',
			usb_setup_request(request),
			description);
}

struct cbw_s {
	uint32_t sig;
	uint32_t tag;
	uint32_t length;
	uint8_t flags;
	uint8_t lun;
	uint8_t cblength;
	uint8_t cbwcb[16];
};

static int find_previous_cbw(struct pctx *pctx, uint32_t tag, int startseq, struct cbw_s *out, uint8_t *buf, int *maxlen)
{
	int seq, len, datalen = 0, tmplen;
	uint32_t ctrl, data;

	seq = startseq;
	while((seq = pctx->func.LAFindSeq(pctx->lactx, seq, -1, -1)) > 0) {
		ctrl = ulpi_get_ctrl_group(pctx, seq);
		if (!(ctrl & ULPI_PID))
			continue;

		data = ulpi_get_data_group(pctx, seq);
		switch(data) {
		case USB_PID_DATA0:
		case USB_PID_DATA1:
		case USB_PID_DATA2:
		case USB_PID_MDATA:
			len = get_usb_packet(pctx, seq, (uint8_t *)out, sizeof(struct cbw_s));
			if (len == 33 && out->sig == 0x43425355 && tag == out->tag) {
				*maxlen = datalen;
				return seq;
			}
			if (datalen < *maxlen) {
				tmplen = get_usb_packet(pctx, seq, buf + datalen, *maxlen - datalen);
				tmplen -= 2;
				if (tmplen < 0)
					tmplen = 0;
				datalen += tmplen;
			}
			continue;
		case USB_PID_NYET:
		case USB_PID_NAK:
		case USB_PID_STALL:
			continue;
		default:
			continue;
		}
	}
	return -1;
}

static void dump_msc_cbw(struct pctx *pctx, struct sequence **firstseq, uint8_t *buf, int len)
{
	struct cbw_s *cbw = (struct cbw_s *)buf;
	sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
			"USB MSC CBW: Tag 0x%04X Length %d Flags %02X LUN %d", cbw->tag, cbw->length, cbw->flags,
			cbw->lun);
	dump_data_to_sequence(pctx, firstseq, cbw->cbwcb, cbw->cblength);
	switch(cbw->cbwcb[0]) {
	case 0x00:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI TEST UNIT READY");
		break;
	case 0x03:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI REQUEST SENSE");
		break;
	case 0x04:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI FORMAT UNIT");
		break;
	case 0x08:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI READ(6)");
		break;
	case 0x0a:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI WRITE(6)");
		break;
	case 0x0b:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI SEEK(6)");
		break;
	case 0x12:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI INQUIRY");
		break;
	case 0x15:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI MODE SELECT");
		break;
	case 0x1a:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI MODE SENSE");
		break;
	case 0x1b:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI START/STOP UNIT");
		break;
	case 0x1e:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI PREVENT/ALLOW MEDIA REMOVAL");
		break;
	case 0x23:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI READ FORMAT CAPACITY");
		break;
	case 0x25:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI READ CAPACITY");
		break;
	case 0x28:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
				"SCSI READ(10): LUN %d, LBA %d, Length %d", cbw->cbwcb[1] >> 5,
				(cbw->cbwcb[2] << 24) | (cbw->cbwcb[3] << 16) | (cbw->cbwcb[4] << 8) | (cbw->cbwcb[5]),
				(cbw->cbwcb[7] << 8) | (cbw->cbwcb[8]));
		break;
	case 0x2a:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
				"SCSI WRITE(10): LUN %d, LBA %d, Length %d", cbw->cbwcb[1] >> 5,
				(cbw->cbwcb[2] << 24) | (cbw->cbwcb[3] << 16) | (cbw->cbwcb[4] << 8) | (cbw->cbwcb[5]),
				(cbw->cbwcb[7] << 8) | (cbw->cbwcb[8]));
		break;
	case 0x2b:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI SEEK");
		break;
	case 0x2c:
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq, "SCSI ERASE");
		break;

	}
}

struct csw_s {
	uint32_t sig;
	uint32_t tag;
	uint32_t dataresidue;
	uint8_t status;
};

static void dump_msc_csw(struct pctx *pctx, struct sequence **firstseq, int startseq, uint8_t *buf, int len)
{
	struct csw_s *csw = (struct csw_s *)buf;
	struct cbw_s cbw;
	uint8_t cbw_buf[4096];
	int seq, cbw_len = sizeof(cbw_buf);

	sequence_printf(pctx, csw->status ? DISPLAY_ATTRIBUTE_ABORTED : DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
			"USB MSC CSW: Tag 0x%04X Data Residue %d, Status %x", csw->tag,
			csw->dataresidue, csw->status);

	if (csw->status)
		return;

	if ((seq = find_previous_cbw(pctx, csw->tag, startseq, &cbw, cbw_buf, &cbw_len)) != -1) {
		switch(cbw.cbwcb[0]) {
		case 0x03:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"REQUEST SENSE: %02X/%02X", cbw_buf[12], cbw_buf[13]);
			break;
		case 0x25:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"READ CAPACITY: LBA %lu, SECTOR SIZE: %lu",
					cbw_buf[3] | cbw_buf[2] << 8 | cbw_buf[1] << 16 | cbw_buf[0] << 24,
					cbw_buf[7] | cbw_buf[6] << 8 | cbw_buf[5] << 16 | cbw_buf[4] << 24);
					break;
		case 0x12:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"INQUIRY");
			break;
		case 0x1a:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"MODE SENSE");
			switch(cbw.cbwcb[2]) {
			case 0x08:
				sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
						"  CACHING");
				break;
			default:
				break;
			}
			break;
		case 0x08:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"READ(6)");
			break;
		case 0x0a:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"WRITE(6)");
			break;

		case 0x28:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"READ(10)");
			break;

		case 0x2a:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"WRITE(10)");
			break;

		default:
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_HIGHLEVEL, firstseq,
					"UNKNOWN CMD %02X", cbw.cbwcb[0]);
			break;
		}
		dump_data_to_sequence(pctx, firstseq, cbw_buf, cbw_len);
	}
}

static void decode_usb_packet(struct pctx *pctx, struct sequence **firstseq,
			      uint8_t *buf, int len, int seq, uint8_t pid)
{
	uint8_t ppid;
	char *token = "UNKNOWN";
	struct sequence *sequence;

	if ((pid & 0x0f) != (~(pid >> 4) & 0xf)) {
		sequence_printf(pctx, DISPLAY_ATTRIBUTE_ABORTED, firstseq,
				"*** INVALID PID: %02X ***", pid);
		return;
	}
	sequence_printf(pctx, DISPLAY_ATTRIBUTE_DECODED, firstseq,
			"%s", pidnames[pid & 0x0f]);

	if (*firstseq) {
		(*firstseq)->group_values[GROUP_PID].value = pid & 0x0f;
		(*firstseq)->group_values[GROUP_PID].mask = 0;
		if (len > 2) {
			(*firstseq)->group_values[GROUP_DATA_SIZE].value = len - 2;
			(*firstseq)->group_values[GROUP_DATA_SIZE].mask = 0;
		}
	}

	switch(pid) {
	case USB_PID_DATA0:
	case USB_PID_DATA1:
	case USB_PID_DATA2:
	case USB_PID_MDATA:
		if (len < 2) {
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_ABORTED, firstseq,
					"short packet");
			break;
		}
		len -= 2;
		ppid = get_previous_pid(pctx, seq);
		if (ppid == USB_PID_SETUP)
			dump_usb_setup_packet(pctx,  firstseq, buf, len, seq);

		if (len >= 31 && !memcmp(buf, "USBC", 4))
			dump_msc_cbw(pctx, firstseq, buf, len);
		else if (len >= 13 && !memcmp(buf, "USBS", 4))
			dump_msc_csw(pctx, firstseq, seq, buf, len);
		else if (pctx->show_buffers && len > 0)
			dump_data_to_sequence(pctx, firstseq, buf, len);
		break;

	case USB_PID_SOF:
		if (len < 2)
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_ABORTED, firstseq,
					"short packet");
		break;

	case USB_PID_SETUP:
	case USB_PID_IN:
	case USB_PID_OUT:

		if (len < 2) {
			sequence_printf(pctx, DISPLAY_ATTRIBUTE_ABORTED, firstseq,
					"  short packet", token);
			break;
		}

		if (*firstseq) {
			(*firstseq)->group_values[GROUP_ADDR].value = buf[0] & 0x7f;
			(*firstseq)->group_values[GROUP_ADDR].mask = 0;
			(*firstseq)->group_values[GROUP_EP].value = (((buf[1] & 0x07) << 1) | ((buf[0] & 0x80) >> 7));
			(*firstseq)->group_values[GROUP_EP].mask = 0;
		}
		break;
	default:
		break;
	}

}

struct sequence *ParseSeq(struct pctx *pctx, int seq)
{
	struct sequence *firstseq = NULL;
	uint8_t ppid, data, ctrl;
	int startseq, len;
	uint8_t buf[4096];

        LogDebug(pctx, 8, "ParseSeq %d\n", seq);

	if (!pctx) {
		LogDebug(pctx, 9, "pctx NULL\n");
		return NULL;
	}

        pctx->displayattribute = pctx->func.LAInfo(pctx->lactx, TLA_INFO_DISPLAY_ATTRIBUTE, -1);

	ctrl = pctx->func.LAGroupValue(pctx->lactx, seq, 1);

	if (!(ctrl & ULPI_PID))
		return NULL;

	if (!(ctrl & ULPI_DATAVALID)) {
		seq = pctx->func.LAFindSeq(pctx->lactx, seq, 1, -1);
		if (seq < 0)
			return NULL;
	}
	data = pctx->func.LAGroupValue(pctx->lactx, seq, 0);

	if (data == USB_PID_SOF && !pctx->show_sof)
		return NULL;

	if (data == USB_PID_IN && !pctx->show_in)
		return NULL;

	if (data == USB_PID_OUT && !pctx->show_out)
		return NULL;

	if (data == USB_PID_NAK && !pctx->show_nak)
		return NULL;

	if (data == USB_PID_ACK && !pctx->show_ack)
		return NULL;

	if (data == USB_PID_NYET && !pctx->show_nyet)
		return NULL;

	if (data == USB_PID_SETUP && !pctx->show_setup)
		return NULL;

	if (data == USB_PID_STALL && !pctx->show_stall)
		return NULL;

	if (data == USB_PID_PING && !pctx->show_ping)
		return NULL;

	if ((data == USB_PID_DATA0 || data == USB_PID_DATA1 || data == USB_PID_DATA2 || data == USB_PID_MDATA) 
	    && !pctx->show_data)
		return NULL;

	len = get_usb_packet(pctx, seq, buf, sizeof(buf));
	decode_usb_packet(pctx, &firstseq, buf, len, seq, data);
	return firstseq;
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
                case SHOW_SOF:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_sof = value;
                        value = pctx->show_sof;
                        break;

                case SHOW_IN:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_in = value;
                        value = pctx->show_in;
                        break;

                case SHOW_OUT:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_out = value;
                        value = pctx->show_out;
                        break;

                case SHOW_NAK:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_nak = value;
                        value = pctx->show_nak;
                        break;
                case SHOW_ACK:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_ack = value;
                        value = pctx->show_ack;
                        break;

                case SHOW_NYET:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_nyet = value;
                        value = pctx->show_nyet;
                        break;

                case SHOW_SETUP:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_setup = value;
                        value = pctx->show_setup;
                        break;

                case SHOW_BUF:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_buffers = value;
                        value = pctx->show_buffers;
                        break;

		case SHOW_DATA:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_data = value;
                        value = pctx->show_data;
                        break;

		case SHOW_PING:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_ping = value;
                        value = pctx->show_ping;
                        break;

		case SHOW_STALL:
                        if (request == 1)
                                return 1;

                        if (request == 2)
                                pctx->show_stall = value;
                        value = pctx->show_stall;
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
	if (pctx)
		return pctx;

	if (!(pctx = func->rda_calloc(1, sizeof(struct pctx)))) {
		func->LAError(0, 9, "Out of Memory");
		return NULL;
	}

        LogDebug(pctx, 8, "%s(%p, %p, %p)\n", __FUNCTION__, pctx, lactx, func);

	pctx->show_sof = 1;
	pctx->show_in = 1;
	pctx->show_out = 1;
	pctx->show_nak = 1;
	pctx->show_ack = 1;
	pctx->show_nyet = 1;
	pctx->show_ping = 1;
	pctx->show_stall = 1;
	pctx->show_data = 1;
	pctx->show_setup = 1;
	pctx->lactx = lactx;
        memcpy(&pctx->func, func, sizeof(struct lafunc));
	return pctx;
}

int ParseDisasmReinit(struct pctx *pctx, int request)
{
        struct seqlog *seqlog;

	LogDebug(pctx, 8, "%s(%p, %d)\n", __FUNCTION__, pctx, request);
        return 1;
}
