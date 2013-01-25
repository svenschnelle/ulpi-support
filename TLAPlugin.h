
#ifndef TLAPLUGIN_H
#define TLAPLUGIN_H

#include <stdint.h>

#define SEQUENCE_TEXT_WIDTH 128

#define GROUP(name, type, _width, _flags, _radix, symbolfile)	\
	{ .groupname = name,\
	  .grouptype = type,\
	  .width = _flags,\
	  .default_columns = _width,\
	  .default_symbolfile = symbolfile, \
	  .field_7 = type == GROUP_TYPE_MNEMONIC ? 1 : 0, \
	  .field_16 = -1,\
	  .default_radix = _radix \
	  }

enum TLA_INFO {
        TLA_INFO_FIRST_SEQUENCE,
        TLA_INFO_LAST_SEQUENCE,
        TLA_INFO_DISPLAY_ATTRIBUTE,
        TLA_INFO_3,
        TLA_INFO_MNEMONICS_WIDTH=5
};

#define ARRAY_SIZE(_x) (sizeof(_x)/sizeof(_x[0]))

typedef enum {
        DISPLAY_ATTRIBUTE_ALL=1,
        DISPLAY_ATTRIBUTE_DECODED,
        DISPLAY_ATTRIBUTE_HIGHLEVEL,
        DISPLAY_ATTRIBUTE_ABORTED,
} display_attribute_t;

struct lactx;

struct businfo {
        const char *name;
	int val4;
	int val8;
	int valc;
	int val10;
	uint16_t val14;
        uint16_t groupcount;
	void *val18;
	int val1c;
};

struct groupinfo {
	char *groupname;
	char field_4;
	char field_5;
	char grouptype;
	char field_7;
	uint16_t width;
	uint16_t default_columns;
	int default_radix;
        const char *default_symbolfile;
        char likegroup;
        char field_15;
        int16_t field_16;
        int16_t field_18;
};

/* mode:
   0 - choicelist / numeric (depending on options value)
   1 - numeric
   2 - choicelist?
   3 - string
   4 - filename
   5 - Button
*/
struct modeinfo {
	char *name;
	void *options;
	int length;
	int mode;
	int radix;
	int symbolic_radix;
};

struct stringmodevalues {
        char *name;
        int val;
};

struct stringmodename {
        int entries;
        char *name;
        struct stringmodevalues *values;
        void *unknown;
};

struct group_value {
        int value;
        int mask;
};

struct sequence {
	struct sequence *next;
	char *textp;
	uint8_t flags;
        char field_9;
        char field_A;
        char field_B;
	struct group_value *group_values;
	int field_10;
	int field_14;
	int field_18;
	int field_1C;
        char text[SEQUENCE_TEXT_WIDTH];
};

struct lafunc {
	int unknown;
	char *support_path;
	char *support_sep;
	char *support_name;
	char *support_name2;
	char *support_ext;
	void *(*rda_malloc)(int size);
	void *(*rda_calloc)(int members, int size);
	void *(*rda_realloc)(void *p, int size);
	void (*rda_free)(void *p);
	void (*LABus)(struct lactx *lactx, int seqno);
	int  (*LAInfo)(struct lactx *, enum TLA_INFO, int16_t bus);
	void (*LAError)(struct lactx *, int, char *, ...);
	int (*LAFindSeq)(struct lactx *, int seq, int skip, int16_t bus);
	char *(*LAFormatValue)(struct lactx *lactx, int group, char *inBuf, int maxLength);
	void (*LAGap)(struct lactx *lactx, int seq);
	int (*LAGroupValue)(struct lactx *lactx, int seqno, int group);
	void (*LAInvalidate)(struct lactx *lactx, int bus, int seq1, int seq2);
	void (*LASeqToText)(struct lactx *lactx, int seq, char *out, int buflen);
	void (*LAGroupWidth)(struct lactx *lactx, int group);
	void (*LATimeStamp_ps)(struct lactx *lactx, int seq, uint64_t *timestamp);
	void (*LASysTrigTime_ps)(struct lactx *lactx, uint64_t *timestamp);
	void (*LABusModTrigTime_ps)(struct lactx *lactx, int bus, int modnum, uint64_t *timestamp);
	void (*LABusModTimeOffset_ps)(struct lactx *lactx, int bus, int modnum, uint64_t *timestamp);
	void (*LAGroupInvalidBitMask)(struct lactx *lactx, int seq, int group);
	void (*LAContigLongToSeq)(struct lactx *lactx, int bus, int seq);
	int (*LALongToSeq)(struct lactx *lactx, int bus, int val);
	int (*LALongToValidSeq)(struct lactx *lactx, int bus, int val1, int val2);
	int (*LASeqToContigLong)(struct lactx *lactx, int seqno);
	void (*LASeqToLong)(struct lactx *lactx, int seqno);
	void (*LASubDisasmLoad)(struct lactx *lactx, void *filename);
	void (*LASubDisasmUnload)(struct lactx *,  void *subdisasm);
	void *(*LASubDisasmFuncTablePtr)(struct lactx *lactx, void *subdisasm);
	int (*LAWhichBusMod)(struct lactx *lactx, int seq);
	int (*LASeqDisplayFormat)(struct lactx *lactx);
	void (*LAInteractiveUI2)(struct lactx *lactx);
	char (*LAProgAbort)(struct lactx *lactx, int seq);
	void (*LATimestamp_ps_ToText)(struct lactx *lactx, uint64_t *timestamp, char *out, int length);
	int (*LATimeStampDisplayFormat)(struct lactx *lactx);
	int (*LAReferenceTime_ps)(struct lactx *lactx, void *out);
	char (*LABusModSysTrigTime_ps)(struct lactx *lactx, int bus, int modnum, void *out);
	void (*LABusModFrameOffset_ps)(struct lactx *lactx, int bus, int modnum, void *out);
	void (*LABusModTimeToUserAlignedTime_ps)(struct lactx *lactx, int bus, int modnum, void *out);
	char (*LABusModTrigSample)(struct lactx *lactx, int bus, int modnum, void *out);
	void (*LABusModWallClockStart)(struct lactx *lactx, int bus, int modnum, uint64_t *);
	void (*LABusModName)(struct lactx *lactx, int bus, int modnum, char *out, int buflen);
	void (*LABusModTimeToUI_Time_ps)(struct lactx *lactx, int bus, int module, uint64_t *timestamp);
	int val; /* returns 4, maybe version? ? */
	int (*LASampleStatusBits)(struct lactx *lactx, int seqno);
	void (*LASampleStatusBitsType)(struct lactx *lactx, int seqno, int bus, int modnum);
	void (*LAGroupViolationBitMask)(struct lactx *lactx, int seqno, int group);
	void (*LAGroupViolationBitMaskType)(struct lactx *lactx, int group);
	void (*LABusModVariantName)(struct lactx *lactx, int bus, int modnum, char *out, int buflen);
	void (*LASystemName)(struct lactx *lactx, int bus, int modnum, char *out, int buflen);
	void (*LASystemPath)(struct lactx *lactx, int bus, int modnum, char *out, int buflen);
	void *field_DC;
};

enum MODEINFO {
	MODEINFO_MAX_BUS=0,
	MODEINFO_MAX_GROUP=1,
	MODEINFO_MAX_MODE=2,
	MODEINFO_3=3,
	MODEINFO_GETNAME=4,
	MODEINFO_MAX,
};

typedef enum {
        GROUP_TYPE_INPUT = 0,
        GROUP_TYPE_1 = 1,
        GROUP_TYPE_MNEMONIC = 2,
        GROUP_TYPE_FAKE_GROUP = 3,
} group_type_t;

__declspec(dllexport) struct pctx *ParseReinit(struct pctx *pctx, struct lactx *lactx, struct lafunc *func);
__declspec(dllexport) int ParseFinish(struct pctx *pctx);
__declspec(dllexport) int ParseInfo(struct pctx *pctx, unsigned int request);
__declspec(dllexport) int ParseMarkMenu(struct pctx *, int seq, char ***, int **, int *);
__declspec(dllexport) int ParseMarkGet(struct pctx *pctx, int seq);
__declspec(dllexport) void ParseMarkSet(struct pctx *pctx, int seq, int mark);
__declspec(dllexport) int ParseMarkNext(struct pctx *pctx, int seq, int *mark);
__declspec(dllexport) int ParseModeGetPut(struct pctx *pctx, int16_t mode, int, int request);
__declspec(dllexport) struct sequence *ParseSeq(struct pctx *, int seq);
__declspec(dllexport) struct businfo *ParseBusInfo(struct pctx *, uint16_t bus);
__declspec(dllexport) struct modeinfo *ParseModeInfo(struct pctx *pctx, uint16_t mode);
__declspec(dllexport) struct groupinfo *ParseGroupInfo(struct pctx *pctx, uint16_t group);
__declspec(dllexport) int ParseDisasmReinit(struct pctx *, int request);
__declspec(dllexport) int ParseExtInfo_(struct pctx *, int request, void *out);
__declspec(dllexport) char *ParseStringModeGetPut_(struct pctx *pctx, int mode, char *value, int request);

#endif
