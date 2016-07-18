/* Copyright (C) 2015 Alcatel-Lucent.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: Koen De Schepper <koen.de_schepper@alcatel-lucent.com>
 * Author: Olga Bondarenko <olgabo@simula.no>
 *
 * PI Improved with a Square (PI2)
 * Supports controlling scalable congestion controls (DCTCP, etc...)
 * Supports DualQ with PI2
 * Supports L4S ECN identifier
 *
 * Based on the PIE implementation:
 * Copyright (C) 2013 Cisco Systems, Inc, 2013.
 * Author: Vijay Subramanian <vijaynsu@cisco.com>
 * Author: Mythili Prabhu <mysuryan@cisco.com>
 * ECN support is added by Naeem Khademi <naeemk@ifi.uio.no>
 * University of Oslo, Norway.
 * References:
 * "PI²: PI Improved with a Square to support Scalable Congestion Controllers"
 * IETF draft submission: http://tools.ietf.org/html/draft-pan-aqm-pie-00
 * IEEE  Conference on High Performance Switching and Routing 2013 :
 * "PIE: A * Lightweight Control Scheme to Address the Bufferbloat Problem"
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define QUEUE_THRESHOLD 10000
#define DQCOUNT_INVALID -1
#define MAX_PROB  0xffffffff
#define PI2_SCALE 8

// remove here if pkt_sched.h is having this:
#ifndef TCA_PI2_MAX
/* PI2 */
enum {
	TCA_PI2_UNSPEC,
	TCA_PI2_TARGET,
	TCA_PI2_LIMIT,
	TCA_PI2_TUPDATE,
	TCA_PI2_ALPHA,
	TCA_PI2_BETA,
	TCA_PI2_ECN,
	TCA_PI2_BYTEMODE,
	TCA_PI2_K,
	TCA_PI2_ECN_SCAL,
	TCA_PI2_L_THRESH,
	TCA_PI2_T_SHIFT,
	__TCA_PI2_MAX
};
#define TCA_PI2_MAX   (__TCA_PI2_MAX - 1)
#endif


/* parameters used */
struct pi2_params {
	psched_time_t target;	/* user specified target delay in pschedtime */
	u32 tupdate;		/* timer frequency (in jiffies) */
	u32 limit;		/* number of packets that can be enqueued */
	u32 alpha;		/* alpha and beta are between 0 and 32 */
	u32 beta;		/* and are used for shift relative to 1 */
	u32 k;			/* coupling rate factor between Classic and L4S */
	u32 ecn;		/* 1 if ecn is enabled, 2 if also dualq is enabled for ect1 and ce, 3 for all ect and ce */
	bool bytemode;		/* to scale drop early prob based on pkt size */

	u32 ecn_scal;	 // which ect to mark scalable (0=none; 1=ect1; 3=all)
	u32 ecn_thresh;	 // packet sized queue size when LL packets get marked
	u16 et_packets_us;  // ecn threshold in packets (0) or us (1)
	u64 tshift;      // LL FIFO time shift (in ns; converted in tune)
	u16 tspeed;      // LL FIFO time speed (in bit shifts)
};

/* variables used */
struct pi2_vars {
	u32 prob;		/* probability but scaled by u32 limit. */
	psched_time_t burst_time;
	psched_time_t qdelay;
	psched_time_t qdelay_old;
	u64 dq_count;		/* measured in bytes */
	psched_time_t dq_tstamp;	/* drain rate */
	u32 avg_dq_rate;	/* bytes per pschedtime tick,scaled */
	u32 qlen_old;		/* in bytes */
};

/* statistics gathering */
struct pi2_stats {
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to pi2_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u32 maxq;		/* maximum queue size */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* private data for the Qdisc */
struct pi2_sched_data {
	struct Qdisc *l_queue;
	struct pi2_params params;
	struct pi2_vars vars;
	struct pi2_stats stats;
	struct timer_list adapt_timer;
	u16 drops_ce;
	u16 drops_ect1;
	u16 drops_ect0;
	u16 drops_nonecn;
};

static void pi2_params_init(struct pi2_params *params)
{
	params->alpha = 10;
	params->beta = 100;
	params->tupdate = usecs_to_jiffies(30 * USEC_PER_MSEC);	/* 30 ms */
	params->limit = 1000;	/* default of 1000 packets */
	params->target = PSCHED_NS2TICKS(20 * NSEC_PER_MSEC);	/* 20 ms */
	params->k = 2;
	params->ecn = 1; // default ecn, no dualq
	params->ecn_scal = 3;  // default all ecn is scalable (for now)
	params->bytemode = false;
	params->ecn_thresh = 1000;	 // packet sized queue size when LL packets get marked
	params->et_packets_us = 1;  // ecn threshold in packets (0) or us (1)
	params->tshift = 40000000;      // LL FIFO time shift (in ns) (40 ms)
	params->tspeed = 0;      // LL FIFO time speed (in bit shifts)
}

static void pi2_vars_init(struct pi2_vars *vars)
{
	vars->dq_count = DQCOUNT_INVALID;
	vars->avg_dq_rate = 0;
	/* default of 100 ms in pschedtime */
	// KDS: disabled burst allowance (too slow for low latency DataCenter access)
	//	vars->burst_time = PSCHED_NS2TICKS(100 * NSEC_PER_MSEC);
	vars->burst_time = 0;
}

static bool drop_early(struct Qdisc *sch, struct pi2_sched_data *q, struct iphdr* iph, struct sk_buff *skb)
{
	u32 packet_size = skb->len;
	u32 rnd;
	u32 local_prob = q->vars.prob;
	u32 mtu = psched_mtu(qdisc_dev(sch));

	/* If there is still burst allowance left skip random early drop */
	if (q->vars.burst_time > 0)
		return false;

	/* If current delay is less than half of target, and
	 * if drop prob is low already, disable early_drop
	 */
	// KDS: squareroot of 1/5 approx 1/2.5 ? Just disable for now...
	//	if ((q->vars.qdelay < q->params.target / 2)
	//	    && (q->vars.prob < MAX_PROB / 5))
	//		return false;

	/* If we have fewer than 2 mtu-sized packets, disable drop_early,
	 * similar to min_th in RED
	 */
	if (sch->qstats.backlog < 2 * mtu)
		return false;

	/* If bytemode is turned on, use packet size to compute new
	 * probablity. Smaller packets will have lower drop prob in this case
	 */
	if (q->params.bytemode && packet_size <= mtu)
		local_prob = (local_prob / mtu) * packet_size;
	else
		local_prob = q->vars.prob;

	rnd = prandom_u32();
	if (q->params.ecn && q->params.ecn_scal && iph && (iph->tos & q->params.ecn_scal)) {// do scalable marking
		if ((rnd < local_prob) && INET_ECN_set_ce(skb)) // mark ecn without a square
			q->stats.ecn_mark++;
	}
	else if (rnd < local_prob/q->params.k) { // if non-scalable mark/drop is needed apply the extra k-factor (rate ratio between classic and L4S)
		// think twice to drop
		rnd = prandom_u32(); // roll again
		if (rnd < local_prob/q->params.k) { // drop/mark Classic
			if (q->params.ecn && INET_ECN_set_ce(skb)) // mark ecn with a square
				q->stats.ecn_mark++;
			else
				return true;
		}
	}
	return false;
}

static void inc_drop_count(struct iphdr* iph, struct pi2_sched_data *q)
{  // KDS: make IP_v6 compatible
	if (iph) {
		if ((iph->tos & 3) == 3)
			q->drops_ce++;
		else if ((iph->tos & 3) == 2)
			q->drops_ect0++;
		else if ((iph->tos & 3) == 1)
			q->drops_ect1++;
		else
			q->drops_nonecn++;
	}
}

static u16 get_drops (struct iphdr* iph, struct pi2_sched_data *q)
{
        u16 drops;
	if ((iph->tos & 3) == 3) {
            drops = q->drops_ce;
			if (drops >= 31)
				drops = 31; // since we can only use 5 bits, max is 32
			q->drops_ce -= drops; // subtract drops we can report, rest is for the following packet
	} else if ((iph->tos & 3) == 2) {
            drops = q->drops_ect0;
			if (drops >= 31)
				drops = 31; // since we can only use 5 bits, max is 32
			q->drops_ect0 -= drops; // subtract drops we can report, rest is for the following packet
	} else if ((iph->tos & 3) == 1) {
            drops = q->drops_ect1;
			if (drops >= 31)
				drops = 31; // since we can only use 5 bits, max is 32
			q->drops_ect1 -= drops; // subtract drops we can report, rest is for the following packet
	} else {
            drops = q->drops_nonecn;
			if (drops >= 31)
				drops = 31; // since we can only use 5 bits, max is 32
			q->drops_nonecn -= drops; // subtract drops we can report, rest is for the following packet
        }
        return drops;
}

static int pi2_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct iphdr* iph = 0;

	// KDS: unused:
	//
	//	bool enqueue = false;

	// set to the time the HTQ packet is in the Q
	__net_timestamp(skb);

	// KDS: make IP_v6 compatible
	if (ntohs(eth_hdr(skb)->h_proto) == ETH_P_IP)
		iph = ip_hdr(skb);

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, q, iph, skb)) {
	// KDS: no need to handle ecn here, moved to and "Improved with
	//      a Square" in drop_early function
	//
	//		enqueue = true;
	//	} else if (q->params.ecn && (q->vars.prob <= MAX_PROB / 10) &&
	//			   INET_ECN_set_ce(skb)) {
	//		/* If packet is ecn capable, mark it if drop probability
	//		 * is lower than 10%, else drop it.
	//		 */
	//		q->stats.ecn_mark++;
	//		enqueue = true;
	//	}
	//
	//	 /* we can enqueue the packet */
	//	if (enqueue) {
		q->stats.packets_in++;
		if (qdisc_qlen(sch) > q->stats.maxq)
			q->stats.maxq = qdisc_qlen(sch);

		if ((q->params.ecn >= 2) && (iph) && (iph->tos & ((q->params.ecn==2)?1:3))) { // mask with ecn for ect1 only or also ect0
			sch->q.qlen++; // otherwise packets are not seen by parent Q
		    qdisc_qstats_backlog_inc(sch, skb);
			return qdisc_enqueue_tail(skb, q->l_queue);
		}
		else
			return qdisc_enqueue_tail(skb, sch);
	}

out:
	q->stats.dropped++;
	inc_drop_count(iph, q);
	return qdisc_drop(skb, sch);
}

static const struct nla_policy pi2_policy[TCA_PI2_MAX + 1] = {
	[TCA_PI2_TARGET] = {.type = NLA_U32},
	[TCA_PI2_LIMIT] = {.type = NLA_U32},
	[TCA_PI2_TUPDATE] = {.type = NLA_U32},
	[TCA_PI2_ALPHA] = {.type = NLA_U32},
	[TCA_PI2_BETA] = {.type = NLA_U32},
	[TCA_PI2_ECN] = {.type = NLA_U32},
	[TCA_PI2_BYTEMODE] = {.type = NLA_U32},
	[TCA_PI2_K] = {.type = NLA_U32},
	[TCA_PI2_ECN_SCAL] = {.type = NLA_U32},
	[TCA_PI2_L_THRESH] = {.type = NLA_U32},
	[TCA_PI2_T_SHIFT] = {.type = NLA_U32},
};

static int pi2_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_PI2_MAX + 1];
	unsigned int qlen;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_PI2_MAX, opt, pi2_policy);
	if (err < 0)
		return err;

	sch_tree_lock(sch);
	if (q->l_queue == &noop_qdisc) {
		struct Qdisc *child;
		child = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
			TC_H_MAKE(sch->handle, 1));
		if (child) {
			q->l_queue = child;
		}
	}

	/* convert from microseconds to pschedtime */
	if (tb[TCA_PI2_TARGET]) {
		/* target is in us */
		u32 target = nla_get_u32(tb[TCA_PI2_TARGET]);

		/* convert to pschedtime */
		q->params.target = PSCHED_NS2TICKS((u64)target * NSEC_PER_USEC);
	}

	/* tupdate is in jiffies */
	if (tb[TCA_PI2_TUPDATE])
		q->params.tupdate = usecs_to_jiffies(nla_get_u32(tb[TCA_PI2_TUPDATE]));

	if (tb[TCA_PI2_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_PI2_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_PI2_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_PI2_ALPHA]);

	if (tb[TCA_PI2_BETA])
		q->params.beta = nla_get_u32(tb[TCA_PI2_BETA]);

	if (tb[TCA_PI2_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_PI2_ECN]);

	if (tb[TCA_PI2_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_PI2_BYTEMODE]);

	if (tb[TCA_PI2_K])
		q->params.k = nla_get_u32(tb[TCA_PI2_K]);

	if (tb[TCA_PI2_ECN_SCAL])
		q->params.ecn_scal = nla_get_u32(tb[TCA_PI2_ECN_SCAL]);

	if (tb[TCA_PI2_L_THRESH])
		q->params.ecn_thresh = nla_get_u32(tb[TCA_PI2_L_THRESH]); /* l_thresh is in us */

	if (tb[TCA_PI2_T_SHIFT]) {
		/* t_shift is in us */
		u32 t_shift = nla_get_u32(tb[TCA_PI2_T_SHIFT]);
		q->params.tshift = (u64)t_shift * NSEC_PER_USEC; // convert to ns
	}

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __skb_dequeue(&sch->q);

		qdisc_qstats_backlog_dec(sch, skb);
		qdisc_drop(skb, sch);
	}
	qdisc_tree_decrease_qlen(sch, qlen - sch->q.qlen);

	sch_tree_unlock(sch);
	return 0;
}

static void pi2_process_dequeue(struct Qdisc *sch, struct sk_buff *skb)
{

	struct pi2_sched_data *q = qdisc_priv(sch);
	int qlen = sch->qstats.backlog - q->l_queue->qstats.backlog;	/* current classic queue size in bytes */
	/* If current queue is about 10 packets or more and dq_count is unset
	 * we have enough packets to calculate the drain rate. Save
	 * current time as dq_tstamp and start measurement cycle.
	 */
	if (qlen >= QUEUE_THRESHOLD && q->vars.dq_count == DQCOUNT_INVALID) {
		q->vars.dq_tstamp = psched_get_time();
		q->vars.dq_count = 0;
	}

	/* Calculate the average drain rate from this value.  If queue length
	 * has receded to a small value viz., <= QUEUE_THRESHOLD bytes,reset
	 * the dq_count to -1 as we don't have enough packets to calculate the
	 * drain rate anymore The following if block is entered only when we
	 * have a substantial queue built up (QUEUE_THRESHOLD bytes or more)
	 * and we calculate the drain rate for the threshold here.  dq_count is
	 * in bytes, time difference in psched_time, hence rate is in
	 * bytes/psched_time.
	 */
	if (q->vars.dq_count != DQCOUNT_INVALID) {
		q->vars.dq_count += skb->len;

		if (q->vars.dq_count >= QUEUE_THRESHOLD) {
			psched_time_t now = psched_get_time();
			u32 dtime = now - q->vars.dq_tstamp;
			u32 count = q->vars.dq_count << PI2_SCALE;

			if (dtime == 0)
				return;

			count = count / dtime;

			if (q->vars.avg_dq_rate == 0)
				q->vars.avg_dq_rate = count;
			else
				q->vars.avg_dq_rate =
				    (q->vars.avg_dq_rate -
				     (q->vars.avg_dq_rate >> 3)) + (count >> 3);

			/* If the queue has receded below the threshold, we hold
			 * on to the last drain rate calculated, else we reset
			 * dq_count to 0 to re-enter the if block when the next
			 * packet is dequeued
			 */
			if (qlen < QUEUE_THRESHOLD)
				q->vars.dq_count = DQCOUNT_INVALID;
			else {
				q->vars.dq_count = 0;
				q->vars.dq_tstamp = psched_get_time();
			}

			if (q->vars.burst_time > 0) {
				if (q->vars.burst_time > dtime)
					q->vars.burst_time -= dtime;
				else
					q->vars.burst_time = 0;
			}
		}
	}
}

static void calculate_probability(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	u32 qlen = sch->qstats.backlog;	/* queue size in bytes */
	psched_time_t qdelay = 0;	/* in pschedtime */
	psched_time_t qdelay_old = q->vars.qdelay;	/* in pschedtime */
	s64 delta = 0;		/* determines the change in probability */
	u32 oldprob;
	u32 alpha, beta;
	bool update_prob = true;


	q->vars.qdelay_old = q->vars.qdelay;

//q->vars.avg_dq_rate = 41;

	if (q->vars.avg_dq_rate > 0)
		qdelay = (qlen << PI2_SCALE) / q->vars.avg_dq_rate;
	else
		qdelay = 0;

	/* If qdelay is zero and qlen is not, it means qlen is very small, less
	 * than dequeue_rate, so we do not update probabilty in this round
	 */
	if (qdelay == 0 && qlen != 0)
		update_prob = false;

	/* In the algorithm, alpha and beta are between 0 and 2 with typical
	 * value for alpha as 0.125. In this implementation, we use values 0-32
	 * passed from user space to represent this. Also, alpha and beta have
	 * unit of HZ and need to be scaled before they can used to update
	 * probability. alpha/beta are updated locally below by 1) scaling them
	 * appropriately 2) scaling down by 16 to come to 0-2 range.
	 * Please see paper for details.
	 *
	 * We scale alpha and beta differently depending on whether we are in
	 * light, medium or high dropping mode.
	 */

	// KDS: disabled scaling, as the square takes care !
	//
	//	if (q->vars.prob < MAX_PROB / 100) {
	//		alpha =
	//		    (q->params.alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 7;
	//		beta =
	//		    (q->params.beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 7;
	//	} else if (q->vars.prob < MAX_PROB / 10) {
	//		alpha =
	//		    (q->params.alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 5;
	//		beta =
	//		    (q->params.beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 5;
	//	} else {
	// KDS: no need to calculate every time ! Move to other location.
		alpha =
		    (q->params.alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 4;
		beta =
		    (q->params.beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 4;
	//	}

	/* alpha and beta should be between 0 and 32, in multiples of 1/16 */
	delta = (s64)((qdelay - q->params.target)) * alpha;
	delta += (s64)((qdelay - qdelay_old)) * beta;

	oldprob = q->vars.prob;

	// KDS: Disable all special threatment for now, maybe revise later in squareroot domain
	//
	//	/* to ensure we increase probability in steps of no more than 2% */
	//	if (delta > (s32) (MAX_PROB / (100 / 2)) &&
	//	    q->vars.prob >= MAX_PROB / 10)
	//		delta = (MAX_PROB / 100) * 2;
	//
	//	/* Non-linear drop:
	//	 * Tune drop probability to increase quickly for high delays(>= 250ms)
	//	 * 250ms is derived through experiments and provides error protection
	//	 */
	//
	//	if (qdelay > (PSCHED_NS2TICKS(250 * NSEC_PER_MSEC)))
	//		delta += MAX_PROB / (100 / 2);

//	if (delta > MAX_PROB)
//	  delta = MAX_PROB;
//	else if (-delta > MAX_PROB)
//	  delta = -(s64)MAX_PROB;
//	else

	q->vars.prob += delta;

	if (delta > 0) {
		/* prevent overflow */
		if (q->vars.prob < oldprob) {
			q->vars.prob = MAX_PROB;
			/* Prevent normalization error. If probability is at
			 * maximum value already, we normalize it here, and
			 * skip the check to do a non-linear drop in the next
			 * section.
			 */
			update_prob = false;
		}
	} else {
		/* prevent underflow */
		if (q->vars.prob > oldprob)
			q->vars.prob = 0;
	}

	/* Non-linear drop in probability: Reduce drop probability quickly if
	 * delay is 0 for 2 consecutive Tupdate periods.
	 */

	if ((qdelay == 0) && (qdelay_old == 0) && update_prob)
		q->vars.prob = (q->vars.prob * 98) / 100;

	q->vars.qdelay = qdelay;
	q->vars.qlen_old = qlen;

	/* We restart the measurement cycle if the following conditions are met
	 * 1. If the delay has been low for 2 consecutive Tupdate periods
	 * 2. Calculated drop probability is zero
	 * 3. We have atleast one estimate for the avg_dq_rate ie.,
	 *    is a non-zero value
	 */
//	if ((q->vars.qdelay < q->params.target / 2) &&
//	    (q->vars.qdelay_old < q->params.target / 2) &&
//	    (q->vars.prob == 0) &&
//	    (q->vars.avg_dq_rate > 0))
//		pi2_vars_init(&q->vars);
}

static void pi2_timer(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc *)arg;
	struct pi2_sched_data *q = qdisc_priv(sch);
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

	spin_lock(root_lock);
	calculate_probability(sch);

	/* reset the timer to fire after 'tupdate'. tupdate is in jiffies. */
	if (q->params.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.tupdate);
	spin_unlock(root_lock);

}

static int pi2_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct pi2_sched_data *q = qdisc_priv(sch);

	pi2_params_init(&q->params);
	pi2_vars_init(&q->vars);
	sch->limit = q->params.limit;
    q->l_queue = &noop_qdisc;
	q->drops_ce = 0;
	q->drops_ect1 = 0;
	q->drops_ect0 = 0;
	q->drops_nonecn = 0;
	setup_timer(&q->adapt_timer, pi2_timer, (unsigned long)sch);

	if (opt) {
		int err = pi2_change(sch, opt);

		if (err)
			return err;
	}

	mod_timer(&q->adapt_timer, jiffies + HZ / 2);
	return 0;
}

static int pi2_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* convert target from pschedtime to us */
	if (nla_put_u32(skb, TCA_PI2_TARGET,
			((u32) PSCHED_TICKS2NS(q->params.target)) /
			NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_PI2_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_PI2_TUPDATE, jiffies_to_usecs(q->params.tupdate)) ||
	    nla_put_u32(skb, TCA_PI2_ALPHA, q->params.alpha) ||
	    nla_put_u32(skb, TCA_PI2_BETA, q->params.beta) ||
	    nla_put_u32(skb, TCA_PI2_ECN, q->params.ecn) ||
	    nla_put_u32(skb, TCA_PI2_BYTEMODE, q->params.bytemode) ||
	    nla_put_u32(skb, TCA_PI2_K, q->params.k) ||
	    nla_put_u32(skb, TCA_PI2_ECN_SCAL, q->params.ecn_scal) ||
	    nla_put_u32(skb, TCA_PI2_L_THRESH, q->params.ecn_thresh) ||
	    nla_put_u32(skb, TCA_PI2_T_SHIFT, ((u32) (q->params.tshift / NSEC_PER_USEC))))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;

}

static int pi2_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct tc_pie_xstats st = {
		.prob		= q->vars.prob,
		.delay		= ((u32) PSCHED_TICKS2NS(q->vars.qdelay)) /
				   NSEC_PER_USEC,
		/* unscale and return dq_rate in bytes per sec */
		.avg_dq_rate	= q->vars.avg_dq_rate *
				  (PSCHED_TICKS_PER_SEC) >> PI2_SCALE,
		.packets_in	= q->stats.packets_in,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.dropped	= q->stats.dropped,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *pi2_qdisc_dequeue(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);

	struct iphdr *iph;
	struct ethhdr *ethh;
	u16 id;
	u32 check;
	u16 drops;
	u64 now = 0;
	u64 qdelay = 0; // delay-based queue size in ms
	u64 qdelay_l;
	u64 qdelay_c;
	u32 lqlen;

	struct sk_buff *skb_l;
	struct sk_buff *skb_c;
	struct sk_buff *skb;

	skb_l = qdisc_peek_head(q->l_queue);
	skb_c = qdisc_peek_head(sch);
	now = ktime_get_real_ns(); // current time in ns
	qdelay_l = (skb_l != NULL) ? (now - ktime_to_ns(skb_get_ktime(skb_l))) : 0; // delay-based queue size in ns
	qdelay_c = (skb_c != NULL) ? (now - ktime_to_ns(skb_get_ktime(skb_c))) : 0; // delay-based queue size in ns

	if (skb_c == NULL) {
		if (skb_l == NULL)
			return NULL;  // no packet at all, just return
		else {
			skb = __qdisc_dequeue_head(q->l_queue, &q->l_queue->q);
		}
	} else if (skb_l == NULL) {
		skb = __qdisc_dequeue_head(sch, &sch->q);
	} else if (q->params.tshift + (qdelay_l << q->params.tspeed) >= qdelay_c) { // if biased L-delay >= C-delay take a L-packet
		skb = __qdisc_dequeue_head(q->l_queue, &q->l_queue->q);
		skb_c = NULL;
	} else { // take a C-packet
		skb = __qdisc_dequeue_head(sch, &sch->q);
		skb_l = NULL;
	}

	if (skb) {
		if (skb_l) {
			sch->q.qlen--;
		    qdisc_qstats_backlog_dec(sch, skb);
		}
	}
	else {
		return NULL;
	}

	if (skb_l != NULL) {  // there is an L4S packet
		qdelay = qdelay_l >> 20; // to ms
		lqlen = qdisc_qlen(q->l_queue);
		if (q->params.et_packets_us
				? (qdelay_l >> 10 > q->params.ecn_thresh) && (lqlen > 0)   // to us; at least still one packet in the queue
				: (lqlen > q->params.ecn_thresh)) {
			// if ECN threshold is exceeded, allways mark
			INET_ECN_set_ce(skb);
		}
	} else { // there must be a Classic packet
		qdelay = qdelay_c >> 20; // to ms
		pi2_process_dequeue(sch, skb);
	}

// KDS: writing drop and delay code is disabled
//	ethh = eth_hdr(skb);
//	if (ntohs(ethh->h_proto) == ETH_P_IP) {
//		iph = ip_hdr(skb);
//		id = ntohs(iph->id);
//		check = ntohs((__force __be16)iph->check);
//		check += id;
//		if ((check+1) >> 16) check = (check+1) & 0xffff;
//              //  id = (__force __u16)sch->q.qlen;
//		if (qdelay > 2047) {
//			pr_info("Large queue delay:  %llu\n", qdelay);
//			qdelay = 2047;
//		}
//		id = (__force __u16) qdelay;
//		drops = get_drops(iph, q);
//		id = id | (drops << 11); // use upper 5 bits in id field to store number of drops before the current packet
//		check -= id;
//		check += check >> 16; /* adjust carry */
//		iph->id = htons(id);
//		iph->check = (__force __sum16)htons(check);
//	}

	return skb;
}

static void pi2_reset(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	qdisc_reset_queue(sch);
	qdisc_reset_queue(q->l_queue);
	pi2_vars_init(&q->vars);
}

static void pi2_destroy(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	q->params.tupdate = 0;
	del_timer_sync(&q->adapt_timer);
	if (q->l_queue != &noop_qdisc)
		qdisc_destroy(q->l_queue);
}

static struct Qdisc_ops pi2_qdisc_ops __read_mostly = {
	.id = "pi2",
	.priv_size	= sizeof(struct pi2_sched_data),
	.enqueue	= pi2_qdisc_enqueue,
	.dequeue	= pi2_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= pi2_init,
	.destroy	= pi2_destroy,
	.reset		= pi2_reset,
	.change		= pi2_change,
	.dump		= pi2_dump,
	.dump_stats	= pi2_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init pi2_module_init(void)
{
	return register_qdisc(&pi2_qdisc_ops);
}

static void __exit pi2_module_exit(void)
{
	unregister_qdisc(&pi2_qdisc_ops);
}

module_init(pi2_module_init);
module_exit(pi2_module_exit);

MODULE_DESCRIPTION("Proportional Integral controller Improved with a Square (PI2) scheduler");
MODULE_AUTHOR("Koen De Schepper");
MODULE_AUTHOR("Olga Bondarenko");
MODULE_AUTHOR("Vijay Subramanian");
MODULE_AUTHOR("Mythili Prabhu");
MODULE_LICENSE("GPL");
