#include <assert.h>
#include <string.h>

#include "statistics.h"

#include "utils.h"


#define LABEL_WIDTH "-40"

static int print_to_file(switch_stats *ss, char * str1, char *str2, FILE *out);
static int add_stats(switch_stats *accumulator, switch_stats * inc);
static int print_labels(char * str1,FILE * out);

/****************************************************
 * int statistics_zero(switch_stats  *ss)
 * 	zero all of the counters
 */

int statistics_zero(switch_stats  *ss)
{
	assert(ss);
	bzero(ss,sizeof(*ss));
	return 0;
}

/***************************************************
 * int statistics_update(switch_stats  *ss, ofpbuf * msg);
 * 	increment the right counter for this msg
 */

int statistics_update(switch_stats  *ss, struct ofpbuf * msg)
{
	struct ofp_header * ofph;
	assert(msg);
	assert(ss);
	ofph = (struct ofp_header * ) msg->data;
	
	assert(ofph->type < STATISTICS_N_COUNTERS);
	ss->ofp_counters[ofph->type]++;

	//fprintf(stderr,"INCR for %d\n",ofph->type);

	return 0;
}

/**********************************************************************
 * int statistics_dump_to_file(struct partition_context * partition_ctx, FILE * out, int should_zero);
 * 	print the statistics to a file in a pretty way and then zero them if should_zero !=0
 */
int statistics_dump_to_file(struct flowvisor_context * fv_ctx, FILE * out, int should_zero)
{
	int i,j;
	struct guest *g;
	struct switch_ *sw;
	struct switch_stats ** total_per_guest;
	// struct switch_stats ** total_per_switch;	 leave per switch data for LATER

	assert(fv_ctx);
	total_per_guest = malloc_and_check(sizeof(struct switch_stats *)* fv_ctx->n_guests);

	print_labels("Guest:switch", out);
	for(i=0;i<fv_ctx->n_guests;i++)
	{
		total_per_guest[i] = malloc_and_check(sizeof(struct switch_stats ));
		statistics_zero(total_per_guest[i]);
		g = &fv_ctx->guests[i];
		for(j=0;j<g->n_switches;j++)
		{
			sw=&g->guest_switches[j];
			print_to_file( &sw->ss,
					fv_ctx->policy->guestName(fv_ctx->policy,g->id),
					fv_ctx->policy->switchName(fv_ctx->policy,sw->id),
					out);
			add_stats(total_per_guest[i],&sw->ss);
			if(should_zero)
				statistics_zero(&sw->ss);
		}
	}

	// fprintf(out,"---------------------------------------------------------------------\n");
	// print_labels("Guest:Total",out);
	fprintf(out,"---------------------------------------------------------"
			"-----------------------------------------------------\n");
	for(i=0;i<fv_ctx->n_guests;i++)
	{
			g = &fv_ctx->guests[i];
			print_to_file( total_per_guest[i],
					fv_ctx->policy->guestName(fv_ctx->policy,g->id),
					"Total",
					out);
			free(total_per_guest[i]);
	}
	fprintf(out,"\n\n");
	free(total_per_guest);
	return 0;
}

/*********************************************************************
 * static int print_labels(char * str1,FILE * out)
 * 	print column headers for the following print_to_file numbers
 */
static int print_labels(char * str1,FILE * out)
{
	fprintf(out,"%" LABEL_WIDTH "s"
			"	pkt_in"
			"	fmods"
			"	pkt_out"
			"	errs"
			"	st_req"
			"	pstats"
			"	vendr"
			"	e_req"
			"	e_rep"
			"	f_exp"
			"	st_rep"
			"	other"
			"	total"
			"\n",str1);
	return 0;
}
/*****************************************************************************
 * static int print_to_file(switch_stats *ss, char * str1, char *str2, FILE *out);
 * 	this proc has to coordinate with print_labels() to match up
 */
static int print_to_file(switch_stats *ss, char * str1, char *str2, FILE *out)
{
	int i, total;
	char buf[BUFLEN];
	total=0;
	snprintf(buf,BUFLEN,"%s:%s",str1,str2);
	for(i=0;i<STATISTICS_N_COUNTERS;i++)
		total+=ss->ofp_counters[i];
	fprintf(out,"%" LABEL_WIDTH "s"
			"	%d"		// pkt_in
			"	%d"		// fmods
			"	%d"		// pkt_out
			"	%d"		// errs"
			"	%d"		// stats_req
			"	%d"		// pstats
			"	%d"		// vendr
			"	%d"		// echo_req
			"	%d"		// echo_rep
			"	%d"		// flow_exp
			"	%d"		// stats_repl
			"	%d"		// other
			"	%d"		// total
			"\n",
			buf,
			ss->ofp_counters[OFPT_PACKET_IN],
			ss->ofp_counters[OFPT_FLOW_MOD],
			ss->ofp_counters[OFPT_PACKET_OUT],
			ss->ofp_counters[OFPT_ERROR],
			ss->ofp_counters[OFPT_STATS_REQUEST],
			ss->ofp_counters[OFPT_PORT_STATUS],
			ss->ofp_counters[OFPT_VENDOR],
			ss->ofp_counters[OFPT_ECHO_REQUEST],
			ss->ofp_counters[OFPT_ECHO_REPLY],
			ss->ofp_counters[OFPT_FLOW_EXPIRED],
			ss->ofp_counters[OFPT_STATS_REPLY],
			total - 
				ss->ofp_counters[OFPT_PACKET_IN] -
				ss->ofp_counters[OFPT_FLOW_MOD] -
				ss->ofp_counters[OFPT_PACKET_OUT] -
				ss->ofp_counters[OFPT_ERROR] -
				ss->ofp_counters[OFPT_STATS_REQUEST] -
				ss->ofp_counters[OFPT_PORT_STATUS] -
				ss->ofp_counters[OFPT_VENDOR] -
				ss->ofp_counters[OFPT_ECHO_REQUEST] -
				ss->ofp_counters[OFPT_ECHO_REPLY] -
				ss->ofp_counters[OFPT_FLOW_EXPIRED] -
				ss->ofp_counters[OFPT_STATS_REPLY],
			total
			);
	return 0;
}

/******************************************************************
 * static int add_stats(switch_stats *accumulator, switch_stats * inc);
 * 	add the second stats to the first one
 */
static int add_stats(switch_stats *accumulator, switch_stats * inc)
{
	int i;
	for(i=0;i<STATISTICS_N_COUNTERS;i++)
		accumulator->ofp_counters[i]+=inc->ofp_counters[i];
	return 0;
}
