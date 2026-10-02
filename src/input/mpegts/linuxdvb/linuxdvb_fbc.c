/*
 *  Tvheadend - Dreambox FBC (Full Band Capture) tuner support
 *
 *  Copyright (C) 2026 Tvheadend
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Phase 1: read-only discovery of the FBC tuner topology via the
 *  /proc/stb/frontend/<n>/... ABI the Dreambox kernel driver exposes.
 *  Nothing here writes to those proc files yet, and nothing here changes
 *  which idclass a frontend is created with - this is purely groundwork
 *  to confirm (via logging, cross-checked against the live device) that
 *  the discovered topology and proc ABI variant match what later phases
 *  will assume before any tuning behavior depends on it.
 *
 *  Discovery algorithm intentionally mirrors enigma2's
 *  eFBCTunerManager (lib/dvb/fbc.cpp) constructor, since that is the
 *  proven, working reference for how to interpret this proc ABI.
 */

#include "tvheadend.h"
#include "linuxdvb_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define FBC_PROC_FMT "/proc/stb/frontend/%d/%s"

typedef enum {
  LINUXDVB_FBC_ABI_NONE,
  LINUXDVB_FBC_ABI_DREAMBOX,
  LINUXDVB_FBC_ABI_GENERIC
} linuxdvb_fbc_abi_t;

/*
 * Low-level proc helpers
 */

static int
linuxdvb_fbc_proc_exists ( int fe, const char *entry )
{
  char path[128];
  snprintf(path, sizeof(path), FBC_PROC_FMT, fe, entry);
  return access(path, R_OK) == 0;
}

static int
linuxdvb_fbc_proc_read_line ( int fe, const char *entry, char *buf, size_t bufsize )
{
  char path[128];
  FILE *fp;

  snprintf(path, sizeof(path), FBC_PROC_FMT, fe, entry);
  if (!(fp = fopen(path, "r")))
    return -1;
  if (!fgets(buf, bufsize, fp)) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

/* Generic ABI: plain integer proc value (e.g. fbc_set_id) */
static int
linuxdvb_fbc_proc_read_int ( int fe, const char *entry )
{
  char buf[32];
  if (linuxdvb_fbc_proc_read_line(fe, entry, buf, sizeof(buf)))
    return -1;
  return atoi(buf);
}

/*
 * Dreambox ABI: the requested entry ("input") holds a bare "A"/"B"
 * token. Mirrors eFBCTunerManager::ReadProcInt()'s DREAMBOX branch
 * exactly, including that any value other than "A" maps to 1.
 */
static int
linuxdvb_fbc_proc_read_ab ( int fe, const char *entry )
{
  char buf[32];
  if (linuxdvb_fbc_proc_read_line(fe, entry, buf, sizeof(buf)))
    return -1;
  return strncmp(buf, "A", 1) == 0 ? 0 : 1;
}

/*
 * Dreambox ABI diagnostic only: input_choices' raw content isn't
 * consumed for role/grouping decisions (enigma2's DREAMBOX branch
 * doesn't use it either - is_root there is the hardcoded "id < 2"
 * rule), but logging it gives visibility into whatever the driver
 * actually reports per slot, to help interpret cases where the
 * "input" A/B boundary-detection heuristic looks ambiguous.
 */
static int
linuxdvb_fbc_read_input_choices ( int fe, char *buf, size_t bufsize )
{
  size_t len;

  if (linuxdvb_fbc_proc_read_line(fe, "input_choices", buf, bufsize))
    return -1;

  len = strlen(buf);
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
    buf[--len] = '\0';

  return 0;
}

/*
 * Generic ABI: fbc_connect_choices is a line containing digit
 * characters, each naming an "id within the set" position that is
 * eligible to act as a root. Mirrors
 * eFBCTunerManager::LoadConnectChoices()'s non-DREAMBOX branch.
 */
static void
linuxdvb_fbc_load_root_choices ( int fe, int choices[8] )
{
  char buf[64];
  const char *p;

  memset(choices, 0, sizeof(int) * 8);

  if (linuxdvb_fbc_proc_read_line(fe, "fbc_connect_choices", buf, sizeof(buf)))
    return;

  for (p = buf; *p; p++) {
    if (isdigit((unsigned char)*p)) {
      int id = *p - '0';
      if (id >= 0 && id < 8)
        choices[id] = 1;
    }
  }
}

static linuxdvb_fbc_abi_t
linuxdvb_fbc_detect_abi ( void )
{
  if (linuxdvb_fbc_proc_exists(0, "fbc_set_id"))
    return LINUXDVB_FBC_ABI_GENERIC;
  if (linuxdvb_fbc_proc_exists(0, "input_choices"))
    return LINUXDVB_FBC_ABI_DREAMBOX;
  return LINUXDVB_FBC_ABI_NONE;
}

/*
 * Probe every possible frontend slot (0-31, matching
 * linuxdvb_adapter_add()'s own frontend-loop range) and build the FBC
 * topology table. Consecutive slots reporting the same "set" value
 * (Dreambox: the "input" A/B value; generic: fbc_set_id) are treated
 * as one hardware FBC group, exactly as enigma2's constructor does -
 * a set boundary is any change in that value between consecutive
 * slot indices.
 */
void
linuxdvb_fbc_probe ( linuxdvb_fbc_slot_t table[32] )
{
  linuxdvb_fbc_abi_t abi;
  int fe, val, prev_set_id, id;
  int root_choices[8];

  for (fe = 0; fe < 32; fe++) {
    table[fe].set_id  = -1;
    table[fe].slot_id = 0;
    table[fe].is_root = 0;
  }

  abi = linuxdvb_fbc_detect_abi();
  if (abi == LINUXDVB_FBC_ABI_NONE) {
    tvhtrace(LS_LINUXDVB, "fbc: no /proc/stb/frontend FBC ABI detected, FBC support inactive");
    return;
  }

  tvhinfo(LS_LINUXDVB, "fbc: detected %s proc ABI",
          abi == LINUXDVB_FBC_ABI_DREAMBOX ? "Dreambox (input A/B)" : "generic (fbc_set_id)");

  prev_set_id = -1;
  id = 0;
  memset(root_choices, 0, sizeof(root_choices));

  for (fe = 0; fe < 32; fe++) {
    if (abi == LINUXDVB_FBC_ABI_DREAMBOX)
      val = linuxdvb_fbc_proc_read_ab(fe, "input");
    else
      val = linuxdvb_fbc_proc_read_int(fe, "fbc_set_id");

    if (val < 0)
      continue; /* slot doesn't exist, or isn't an FBC slot */

    if (val != prev_set_id) {
      prev_set_id = val;
      id = 0;
      if (abi == LINUXDVB_FBC_ABI_GENERIC)
        linuxdvb_fbc_load_root_choices(fe, root_choices);
    }

    table[fe].set_id  = val;
    table[fe].slot_id = id;

    if (abi == LINUXDVB_FBC_ABI_DREAMBOX)
      table[fe].is_root = id < 2;
    else
      table[fe].is_root = (id < 8) && root_choices[id];

    tvhinfo(LS_LINUXDVB, "fbc: proc slot %d -> set_id=%d slot_id=%d role=%s",
            fe, table[fe].set_id, table[fe].slot_id,
            table[fe].is_root ? "root" : "leaf");

    if (abi == LINUXDVB_FBC_ABI_DREAMBOX) {
      char choices[64];
      if (!linuxdvb_fbc_read_input_choices(fe, choices, sizeof(choices)))
        tvhinfo(LS_LINUXDVB, "fbc: proc slot %d -> input_choices=\"%s\"",
                fe, choices);
      else
        tvhinfo(LS_LINUXDVB, "fbc: proc slot %d -> input_choices=<none>", fe);
    }

    id++;
  }
}
