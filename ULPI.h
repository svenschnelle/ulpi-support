
#ifndef ULPI_H
#define ULPI_H

#include <stdint.h>
#include "TLAPlugin.h"

#define SEQUENCE_TEXT_WIDTH 64

struct pctx {
	struct lactx *lactx;
	struct lafunc func;
	int displayattribute;
	int lastctrl;
	int lastdata;
	int show_sof;
	int show_buffers;
};

#endif
