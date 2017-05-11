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
#include "ox-stat.h"

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
void oxs_put__(struct ofpbuf *b, enum oxs_ofb_stat_fields field,
               enum ofp_version version,
               const void *value, const void *mask, size_t n_bytes);
static enum ofperr oxs_pull_agg_raw(const uint8_t *p, unsigned int stat_len,
                                    struct ofputil_aggregate_stats *fs);

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

static enum ofperr
oxs_pull_entry__(struct ofpbuf *b, uint64_t *header,
                 const struct oxs_field **field_,struct ofputil_flow_stats *fs)
{
    const struct oxs_field *field;
    enum ofperr header_error;
    unsigned int payload_len;
    const uint8_t *payload;

    header_error = oxs_pull_header__(b, header, &field);

    if (header_error && header_error != OFPERR_OFPBMC_BAD_FIELD) {
        return header_error;
    }

    payload_len = oxs_payload_len(*header);
    payload = ofpbuf_try_pull(b, payload_len);
    if (!payload) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    if(fs && field){
      switch(field->id)
      {
            case OFPXST_OFB_DURATION:
            {
                    uint64_t duration=0;
                    memcpy(&duration,payload,sizeof(duration));
                            duration = ntohll(duration);
                     fs->duration_sec = ((uint32_t)((duration &
                                          0xFFFFFFFF00000000) >> 32));
                     fs->duration_nsec = ((uint32_t)(duration & 0xFFFFFFFF));
            }
            break;
            case OFPXST_OFB_IDLE_TIME:
            {
                    uint64_t idle_time=0;
                    memcpy(&idle_time,payload,sizeof(idle_time));
                            idle_time = ntohll(idle_time);
                     fs->idle_age = ((idle_time & 0xFFFFFFFF00000000)  >> 32);
            }
            break;
            case OFPXST_OFB_PACKET_COUNT:
            {
                    uint64_t packet_count;
                    memcpy(&packet_count,payload,sizeof(packet_count));
                    fs->packet_count = ntohll(packet_count);
            }
            break;
            case OFPXST_OFB_BYTE_COUNT:
            {
                    uint64_t byte_count;
                    memcpy(&byte_count,payload,sizeof(byte_count));
                    fs->byte_count = ntohll(byte_count);
            }
            break;
            case OFPXST_OFB_FLOW_COUNT:
            break;
        }
     }

     if (field_) {
         *field_ = field;
         return header_error;
     }

     return 0;
}

static enum ofperr
oxs_pull_match_entry(struct ofpbuf *b,
                     const struct oxs_field **field,
                     struct ofputil_flow_stats *fs)
{
    enum ofperr error;
    uint64_t header;

    error = oxs_pull_entry__(b, &header, field,fs);
    if (error) {
        return error;
    }
   return 0;
}

static enum ofperr
oxs_pull_raw(const uint8_t *p, unsigned int stat_len,
             struct ofputil_flow_stats *fs,
             ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    ovs_assert((cookie != NULL) == (cookie_mask != NULL));
    if (cookie) {
        *cookie = *cookie_mask = htonll(0);
    }

    struct ofpbuf b = ofpbuf_const_initializer(p, stat_len);

    while (b.size) {
        const uint8_t *pos = b.data;
        const struct oxs_field *field;
        union mf_value value;
        union mf_value mask;
        enum ofperr error;
        error = oxs_pull_match_entry(&b, &field,fs);
        if (error) {
            if (error == OFPERR_OFPBMC_BAD_FIELD && !false) {
                continue;
            }
        }
        else if (!field) {
             if (!cookie) {
                error = OFPERR_OFPBMC_BAD_FIELD;
            } else if (*cookie_mask) {
                error = OFPERR_OFPBMC_DUP_FIELD;
            } else {
                *cookie = value.be64;
                *cookie_mask = mask.be64;
            }
      }
      else {
            if(field->id == OFPXST_OFB_DURATION) {
                 oxs_field_set |= 1<<0;
            } else if(field->id == OFPXST_OFB_IDLE_TIME) {
                 oxs_field_set |= 1<<1;
            } else if(field->id == OFPXST_OFB_FLOW_COUNT) {
                 oxs_field_set |= 1<<2;
            } else if(field->id == OFPXST_OFB_PACKET_COUNT) {
                 oxs_field_set |= 1<<3;
            } else if(field->id == OFPXST_OFB_BYTE_COUNT) {
                 oxs_field_set |= 1<<4;
            }
          }
        if (error) {
            VLOG_DBG_RL(&rl, "error parsing OXS at offset %"PRIdPTR" "
                        "within match (%s)", pos -
                        p, ofperr_to_string(error));
            return error;
        }
    }
    return 0;
}

int oxs_pull_stat(struct ofpbuf *b,struct ofputil_flow_stats *fs,
                  uint16_t *statlen)
{
    struct  ofp_oxs_stat *oxs = b->data;
    uint8_t *p;
    uint16_t stat_len;
    stat_len = ntohs(oxs->length);
    if (stat_len < sizeof *oxs) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    p = ofpbuf_try_pull(b, ROUND_UP(stat_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "oxs length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %"PRIu32")", stat_len, b->size);
        return OFPERR_OFPBMC_BAD_LEN;
    }
    *statlen = ROUND_UP(stat_len, 8);
    return oxs_pull_raw(p + sizeof *oxs, stat_len - sizeof *oxs,fs,
                         NULL, NULL);
}

static enum ofperr
oxs_pull_agg_raw(const uint8_t *p, unsigned int stat_len,
                struct ofputil_aggregate_stats *fs)
{
    struct ofpbuf b = ofpbuf_const_initializer(p, stat_len);

    while (b.size) {

      uint64_t header;
      unsigned int payload_len;
      const struct oxs_field *field;
      const uint8_t *payload;

      oxs_pull_header__(&b,&header,&field);
      payload_len = oxs_payload_len(header);
      payload = ofpbuf_try_pull(&b, payload_len);

      if(fs && field) {
       switch(field->id)
        {
             case OFPXST_OFB_FLOW_COUNT:
             {
               uint32_t flow_count=0;
               memcpy(&flow_count,payload,sizeof(flow_count));
               fs->flow_count = ntohl(flow_count);
             }
             break;
             case OFPXST_OFB_PACKET_COUNT:
             {
               uint64_t packet_count;
               memcpy(&packet_count,payload,sizeof(packet_count));
               fs->packet_count = ntohll(packet_count);
             }
             break;
             case OFPXST_OFB_BYTE_COUNT:
             {
               uint64_t byte_count;
               memcpy(&byte_count,payload,sizeof(byte_count));
               fs->byte_count = ntohll(byte_count);
            }
             break;
             case OFPXST_OFB_DURATION:
             case OFPXST_OFB_IDLE_TIME:
             break;
        }

     }

    }
    return 0;
}

int
oxs_pull_agg_stat(struct ofpbuf b, struct ofputil_aggregate_stats *fs)
{
    struct  ofp_oxs_stat *oxs = b.data;
    uint8_t *p;
    uint16_t stat_len;

    stat_len = ntohs(oxs->length);

    if (stat_len < sizeof *oxs) {
      return OFPERR_OFPBMC_BAD_LEN;
    }

    p = ofpbuf_try_pull(&b, ROUND_UP(stat_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "oxs length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %"PRIu32")", stat_len, b.size);
        return OFPERR_OFPBMC_BAD_LEN;
    }

    return oxs_pull_agg_raw(p + sizeof *oxs, stat_len - sizeof *oxs,fs);
}

static struct hmap oxs_header_map;
static struct hmap oxs_name_map;


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

static const struct oxs_field *
oxs_field_by_header(uint32_t header)
{
   const struct oxs_field_index *oxfs;
   uint32_t header_no_len;

   oxs_init();

   header_no_len = oxs_header_no_len(header);
   HMAP_FOR_EACH_IN_BUCKET (oxfs, header_node, hash_int(header_no_len,0),
                            &oxs_header_map) {
     if (header_no_len == oxs_header_no_len(oxfs->fs.header)) {
       if (OXS_LENGTH(header) == OXS_LENGTH(oxfs->fs.header)) {
           return &oxfs->fs;
           } else {
             return NULL;
           }
       }
   }
   return NULL;
}

static const struct oxs_field *
oxs_field_by_id(enum oxs_ofb_stat_fields id, enum ofp_version version)
{
   const struct oxs_field_index *oxfs;
   const struct oxs_field *fs=NULL;

   oxs_init();

   LIST_FOR_EACH (oxfs, ox_node, &oxs_ox_map[id]) {
       if (!fs || version >= oxfs->fs.version) {
           fs = &oxfs->fs;
       }
   }
   return fs;
}

static void
oxs_put_header__(struct ofpbuf *b, uint64_t header)
{
    ovs_be32 network_header = htonl(header);
    ofpbuf_put(b, &network_header, oxs_header_len(header));
}


static void
oxs_put_header_len(struct ofpbuf *b, enum oxs_ofb_stat_fields field,
                   enum ofp_version version)
{
    uint32_t header = oxs_header_get(field, version);
    header = OXS_HEADER(OXS_CLASS(header),
                        OXS_FIELD(header),
                        OXS_LENGTH(header));
    oxs_put_header__(b, header);
}

void oxs_put__(struct ofpbuf *b, enum oxs_ofb_stat_fields field,
               enum ofp_version version,
               const void *value, const void *mask, size_t n_bytes)
{
    oxs_put_header_len(b, field, version);
    ofpbuf_put(b, value, n_bytes);
    if (mask) {
        ofpbuf_put(b, mask, n_bytes);
    }

}

static int
ox_put_raw(struct ofpbuf *b, enum ofp_version oxs,
           const struct ofputil_flow_stats *fs,
           ovs_be64 cookie, ovs_be64 cookie_mask)
{
  const size_t start_len = b->size;
  int stat_len;
  if (oxs_field_set & 1<<0) {
  uint64_t duration = 0;
       if(fs){
           duration = (uint64_t) fs->duration_sec << 32 |
                      fs->duration_nsec;
                      duration = htonll(duration);
          }
          oxs_put__(b, OFPXST_OFB_DURATION, oxs, &duration, NULL,
                     OXS_STATS_DURATION_LEN);
       }
       if (oxs_field_set & 1<<1) {
               uint64_t idl_time = 0;
               if(fs){
                        idl_time = (uint64_t)fs->idle_age <<32 ;
                       idl_time = htonll(idl_time);
               }
               oxs_put__(b, OFPXST_OFB_IDLE_TIME, oxs, &idl_time, NULL,
                          OXS_STATS_IDLE_TIME_LEN);
       }
       if (oxs_field_set & 1<<2) {
               uint32_t flow_count = 0;
                oxs_put__(b, OFPXST_OFB_FLOW_COUNT, oxs, &flow_count, NULL,
                          OXS_STATS_FLOW_COUNT_LEN);
       }
       if (oxs_field_set & 1<<3) {
               uint64_t pkt_count = 0;
               if(fs){
                     pkt_count = fs->packet_count;
                    pkt_count = htonll(pkt_count);
               }
               oxs_put__(b, OFPXST_OFB_PACKET_COUNT, oxs, &pkt_count, NULL,
                          OXS_STATS_PACKET_COUNT_LEN);
       }
       if (oxs_field_set & 1<<4) {
               uint64_t byte_count = 0;
               if(fs){
                     byte_count = fs->byte_count;
                    byte_count = htonll(byte_count);
               }
               oxs_put__(b, OFPXST_OFB_BYTE_COUNT, oxs, &byte_count, NULL,
                          OXS_STATS_BYTE_COUNT_LEN);
       }
       if (cookie_mask) {
               cookie &= cookie_mask;
               oxs_put_header__(b, OXS_OX_COOKIE);
               ofpbuf_put(b, &cookie, sizeof cookie);
       }
       stat_len = b->size - start_len;
       return stat_len;
}

int
oxs_put_stat(struct ofpbuf *b, const struct ofputil_flow_stats *fs,
             enum ofp_version version)
{
    int stat_len;
    struct ofp_oxs_stat *oxs;
    size_t start_len = b->size;
    ovs_be64 cookie = htonll(0), cookie_mask = htonll(0);
    ofpbuf_put_uninit(b, sizeof *oxs);
    stat_len = (ox_put_raw(b, version, fs, cookie, cookie_mask)
                 + sizeof *oxs);
    ofpbuf_put_zeros(b, PAD_SIZE(stat_len, 8));
    oxs = ofpbuf_at(b, start_len, sizeof *oxs);
    oxs->reserved = htons(0);
    oxs->length = htons(stat_len);
    return stat_len;
}

static int
ox_put_agg_raw(struct ofpbuf *b, enum ofp_version oxs,
               const struct ofputil_aggregate_stats *fs)
{
   const size_t start_len = b->size;
   int stat_len;

   if (oxs_field_set & 1<<2) {
     uint32_t flow_count = 0;
     if(fs) {
       flow_count=fs->flow_count;
       flow_count=htonl(flow_count);
     }
     oxs_put__(b, OFPXST_OFB_FLOW_COUNT, oxs, &flow_count,
                NULL, OXS_STATS_FLOW_COUNT_LEN);
   }

   if (oxs_field_set & 1<<3) {
     uint64_t pkt_count = 0;
    if(fs) {
        pkt_count = fs->packet_count;
        pkt_count = htonll(pkt_count);
     }
     oxs_put__(b, OFPXST_OFB_PACKET_COUNT, oxs, &pkt_count,
               NULL, OXS_STATS_PACKET_COUNT_LEN);
   }

   if (oxs_field_set & 1<<4) {
      uint64_t byte_count = 0;
      if(fs) {
        byte_count = fs->byte_count;
        byte_count = htonll(byte_count);
      }
      oxs_put__(b, OFPXST_OFB_BYTE_COUNT, oxs, &byte_count,
                NULL, OXS_STATS_BYTE_COUNT_LEN);
   }

   stat_len = b->size - start_len;
   return stat_len;
}

int
oxs_put_agg_stat(struct ofpbuf *b, const struct ofputil_aggregate_stats *fs,
                 enum ofp_version version)
{
   int stat_len;
   struct ofp_oxs_stat *oxs;
   size_t start_len = b->size;

   ofpbuf_put_uninit(b, sizeof *oxs);
   stat_len = (ox_put_agg_raw(b, version, fs)
                + sizeof *oxs);
   ofpbuf_put_zeros(b, PAD_SIZE(stat_len, 8));
   oxs = ofpbuf_at(b, start_len, sizeof *oxs);
   oxs->reserved = htons(0);
   oxs->length = htons(stat_len);

   return stat_len;
}

