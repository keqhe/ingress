#ifndef STATISTICS_H
#define STATISTICS_H

#include <stdio.h>

#ifndef STATISTICS_FILE
#define STATISTICS_FILE "./flowvisor.stats"
#endif

#include <openflow/openflow.h>
// FIXME: find a cleaner way to updated this when openflow.h changes

#define STATISTICS_N_COUNTERS (OFPT_STATS_REPLY+1)	// the last enum + 1

typedef struct switch_stats
{
	int ofp_counters[STATISTICS_N_COUNTERS];	// one counter for each type of message
} switch_stats;
#include "flowvisor.h"
#include "ofpbuf.h"





int statistics_zero(struct switch_stats  *ss);
int statistics_update(struct switch_stats  *ss, struct ofpbuf * msg);
int statistics_dump_to_file(struct flowvisor_context * fv_ctx, FILE * out, int should_zero);


#endif
