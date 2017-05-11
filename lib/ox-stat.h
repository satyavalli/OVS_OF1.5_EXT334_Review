/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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

#ifndef OX_STAT_H
#define OX_STAT_H 1

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "compiler.h"
#include "flow.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/types.h"

int oxs_put_stat(struct ofpbuf *, const struct ofputil_flow_stats *,
                 enum ofp_version);
int oxs_pull_stat(struct ofpbuf *,struct ofputil_flow_stats *,
                  uint16_t *);

#endif /* ox_stat.h */

