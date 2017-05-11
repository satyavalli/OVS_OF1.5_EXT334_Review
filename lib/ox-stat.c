/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
 */

#include <config.h>
#include "nx-match.h"
#include "ox-stat.h"
#include <netinet/icmp6.h>
#include "classifier.h"
#include "colors.h"
#include "openvswitch/hmap.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "openvswitch/shash.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ox_stat);

/* ## -------------------------- ## */
/* ## OpenFlow Extensible Stats. ## */
/* ## -------------------------- ## */

/* Components of a OXS TLV header. */

static struct ovs_list oxs_ox_map[OFPXST_OFB_BYTE_COUNT + 1];
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static uint32_t oxs_header_no_len(uint32_t header) {
                return header & 0xffffff80; }

#define OXS_CLASS(HEADER) ((HEADER) >> 16)
#define OXS_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define OXS_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define OXS_RESERVED(HEADER) (((HEADER) >> 8) & 1)
#define OXS_LENGTH(HEADER) ((HEADER) & 0xff)

/* Components of a OXS TLV header. */
#define OXS_HEADER__(CLASS, FIELD, RESERVED, LENGTH) \
(((CLASS) << 16) | ((FIELD) << 9) | ((RESERVED) << 8) | (LENGTH))


#define OXS_HEADER(CLASS, FIELD, LENGTH) \
        OXS_HEADER__(CLASS, FIELD, 0, LENGTH)


/*  OXS Class IDs.
 *  The high order bit differentiate reserved classes from member classes.
 *  Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
 *  Classes 0x8000 to 0xFFFE are reserved classes, reserved for
 *  standardisation.
 */

enum ofp_oxs_class {
  OFPXSC_OPENFLOW_BASIC = 0x8002,   /* Basic stats class for OpenFlow */
  OFPXSC_EXPERIMENTER   = 0xFFFF,   /* Experimenter class */
};


#define OFPXST_OFB_ALL ((UINT64_C(1) << 6) - 1)
#define OXS_OX_COOKIE    OXS_HEADER  (0x8002, 5 , 8)

struct oxs_field {
    uint32_t header;
    enum ofp_version version;
    const char *name;
    enum oxs_ofb_stat_fields id;
};

struct oxs_field_index {
    struct hmap_node header_node;
    struct hmap_node name_node;
    struct ovs_list ox_node;
    const struct oxs_field fs;
};

#define OXS_STATS_DURATION_LEN     8
#define OXS_STATS_IDLE_TIME_LEN    8
#define OXS_STATS_FLOW_COUNT_LEN   4
#define OXS_STATS_PACKET_COUNT_LEN 8
#define OXS_STATS_BYTE_COUNT_LEN   8

#define OXS_OF_DURATION     OXS_HEADER (0x8002, OFPXST_OFB_DURATION, \
                                        OXS_STATS_DURATION_LEN)
#define OXS_OF_IDLE_TIME    OXS_HEADER (0x8002, OFPXST_OFB_IDLE_TIME, \
                                        OXS_STATS_IDLE_TIME_LEN)
#define OXS_OF_FLOW_COUNT   OXS_HEADER (0x8002, OFPXST_OFB_FLOW_COUNT, \
                                        OXS_STATS_FLOW_COUNT_LEN)
#define OXS_OF_PACKET_COUNT OXS_HEADER (0x8002, OFPXST_OFB_PACKET_COUNT, \
                                        OXS_STATS_PACKET_COUNT_LEN)
#define OXS_OF_BYTE_COUNT   OXS_HEADER (0x8002, OFPXST_OFB_BYTE_COUNT, \
                                        OXS_STATS_BYTE_COUNT_LEN)

static struct oxs_field_index all_oxs_fields[] = {
{.fs = { OXS_OF_DURATION, OFP15_VERSION, "OFPXST_OFB_DURATION",
         OFPXST_OFB_DURATION } },
{.fs = { OXS_OF_IDLE_TIME, OFP15_VERSION, "OFPXST_OFB_IDLE_TIME",
         OFPXST_OFB_IDLE_TIME } },
{.fs = { OXS_OF_FLOW_COUNT, OFP15_VERSION, "OFPXST_OFB_FLOW_COUNT",
         OFPXST_OFB_FLOW_COUNT } },
{.fs = { OXS_OF_PACKET_COUNT, OFP15_VERSION, "OFPXST_OFB_PACKET_COUNT",
         OFPXST_OFB_PACKET_COUNT } },
{.fs = { OXS_OF_BYTE_COUNT, OFP15_VERSION, "OFPXST_OFB_BYTE_COUNT",
         OFPXST_OFB_BYTE_COUNT } },
};

uint8_t oxs_field_set;

static const struct oxs_field *oxs_field_by_header(uint32_t header);
static const struct oxs_field *oxs_field_by_id(enum oxs_ofb_stat_fields,
                                               enum ofp_version);
int oxs_put_stat(struct ofpbuf *b, struct ofputil_flow_stats *fs,
                 enum ofp_version version);

static bool
is_experimenter_oxs(uint64_t header)
{
   return OXS_CLASS(header) == OFPXSC_EXPERIMENTER;
}

static int
oxs_experimenter_len(uint64_t header)
{
   return is_experimenter_oxs(header) ? 4 : 0;
}

static int
oxs_payload_len(uint64_t header)
{
   return OXS_LENGTH(header) - oxs_experimenter_len(header);
}

static int
oxs_header_len(uint64_t header)
{
   return 4 + oxs_experimenter_len(header);
}

static uint64_t
oxs_header_get(enum oxs_ofb_stat_fields id, enum ofp_version version)
{
   const struct oxs_field *f = oxs_field_by_id(id, version);
   return f ? f->header : 0;
}

static int
oxs_pull_header__(struct ofpbuf *b, uint64_t *header,
                  const struct oxs_field **field)
{
    if (b->size < 4) {
        goto bad_len;
    }

    *header = ((uint32_t) ntohl(get_unaligned_be32(b->data))) ;

    if (is_experimenter_oxs(*header)) {
        if (b->size < 8) {
            goto bad_len;
        }

        *header = ntohll(get_unaligned_be64(b->data));
    }

    if (OXS_LENGTH(*header) < oxs_experimenter_len(*header)) {
        goto error;
    }

    ofpbuf_pull(b, oxs_header_len(*header));

    if (field) {
        *field = oxs_field_by_header(*header);
        if (!*field || (*field==NULL)) {
            return OFPERR_OFPBMC_BAD_FIELD;
        }
    }
    return 0;


bad_len:
    VLOG_DBG_RL(&rl, "encountered partial (%"PRIu32"-byte) OXS entry",
                b->size);
error:
    *header = 0;
    if (field) {
        *field = NULL;
    }
    return OFPERR_OFPBMC_BAD_LEN;
}

static void
oxs_init(void)
{
   static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
   if (ovsthread_once_start(&once)) {
         hmap_init(&oxs_header_map);
         hmap_init(&oxs_name_map);
         for (int i = 0; i < OFPXST_OFB_BYTE_COUNT + 1; i++) {
              ovs_list_init(&oxs_ox_map[i]);
         }
         for (struct oxs_field_index *oxfs = all_oxs_fields;
              oxfs < &all_oxs_fields[ARRAY_SIZE(all_oxs_fields)]; oxfs++) {
              hmap_insert(&oxs_header_map, &oxfs->header_node,
                          hash_int(oxs_header_no_len(oxfs->fs.header),0));
              hmap_insert(&oxs_name_map, &oxfs->name_node,
                          hash_string(oxfs->fs.name, 0));
              ovs_list_push_back(&oxs_ox_map[oxfs->fs.id], &oxfs->ox_node);
         }
         ovsthread_once_done(&once);
    }
}



