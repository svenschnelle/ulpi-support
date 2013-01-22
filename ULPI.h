
#ifndef ULPI_H
#define ULPI_H

#include <stdint.h>
#include "TLAPlugin.h"

#define SEQUENCE_TEXT_WIDTH 128

struct pctx {
	struct lactx *lactx;
	struct lafunc func;
	int displayattribute;
	int lastctrl;
	int lastdata;
	int show_sof;
	int show_in;
	int show_out;
	int show_nak;
	int show_ack;
	int show_nyet;
	int show_data;
	int show_setup;
	int show_stall;
	int show_ping;
	int show_buffers;
};

#endif
