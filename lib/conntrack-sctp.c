/*
 * Copyright (c) 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Implements a connection tracker for the sctp protocol.
 */

#include <config.h>

#include "conntrack-private.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "util.h"

#define SCTP_TRACK_DIR_ORIG   0
#define SCTP_TRACK_DIR_REPL   1
#define SCTP_TRACK_DIRECTIONS 2

#define ISTATES CT_DPIF_SCTP_STATE_MAX_NUM
#define OSTATES CT_DPIF_SCTP_STATE_MAX_NUM

struct conn_sctp {
    struct conn c;
    uint8_t state;
    uint32_t vtag[SCTP_TRACK_DIRECTIONS];
};

/* shortened names */
#define CL CT_DPIF_SCTP_STATE_CLOSED
#define CW CT_DPIF_SCTP_STATE_COOKIE_WAIT
#define CE CT_DPIF_SCTP_STATE_COOKIE_ECHOED
#define ET CT_DPIF_SCTP_STATE_ESTABLISHED
#define SS CT_DPIF_SCTP_STATE_SHUTDOWN_SENT
#define SR CT_DPIF_SCTP_STATE_SHUTDOWN_RECD
#define SA CT_DPIF_SCTP_STATE_SHUTDOWN_ACK_SENT
#define HS CT_DPIF_SCTP_STATE_HEARTBEAT_SENT
#define HA CT_DPIF_SCTP_STATE_HEARTBEAT_ACKED

#define FOR_EACH_CHUNK(packet, chunkhdr_p, chunkhdr, off, dataoff, count) \
    for ((off) = (dataoff) + sizeof(struct sctp_header), (count) = 0;     \
         (off) < dp_packet_size((packet)) &&                              \
         ((chunkhdr_p) =                                                  \
          (struct sctp_chunk *)((char *)dp_packet_data(packet) + off));   \
         (count) += 1, (off) += (ntohs(chunkhdr_p)->len))

static const uint8_t sctp_state_maps[SCTP_TRACK_DIRECTIONS][ISTATES][OSTATES] =
{
    {
     /* ORIG direction */
     /* 'closed' */
     {CL, CW, CE, ET, SS, SR, SA, CL, HA},
     /* */
     {CL, CL, CL, CL, CL, CL, CL, CL, CL},
    },
    {
     /* REPLY direction */
     {},
    }
};

static struct conn_sctp *
conn_sctp_cast(const struct conn *conn)
{
    return CONTAINER_OF(conn, struct conn_sctp, c);
}


static struct conn *
sctp_new_conn(struct conntrack_bucket *ctb OVS_UNUSED,
              struct dp_packet *pkt OVS_UNUSED,
              long long now OVS_UNUSED)
{
    struct conn_sctp *newconn = xzalloc(sizeof(struct conn_sctp));
    /* struct sctp_header *header = dp_packet_l4(pkt); */

    newconn->state = sctp_state_maps[SCTP_TRACK_DIR_ORIG][0][0];
    return newconn;
}

static void
sctp_conn_get_protoinfo(const struct conn *conn_,
                        struct ct_dpif_protoinfo *protoinfo)
{
    const struct conn_sctp *conn = conn_sctp_cast(conn_);

    protoinfo->proto = IPPROTO_SCTP;
    protoinfo->sctp.state = conn->state;
    protoinfo->sctp.vtag_orig = conn->vtag[0];
    protoinfo->sctp.vtag_reply = conn->vtag[1];
}

struct ct_l4_proto ct_proto_sctp = {
    .new_conn = sctp_new_conn,
    /* .valid_new = sctp_valid_new,
       .conn_update = sctp_conn_update, */
    .conn_get_protoinfo = sctp_conn_get_protoinfo,
};
