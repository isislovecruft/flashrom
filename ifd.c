/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2013 secunet Security Networks AG
 *
 * ifd reading code borrowed from coreboot's ifdtool:
 * Copyright (C) 2011 The ChromiumOS Authors.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdint.h>
#include <stdio.h>
#include "flash.h"

/* flash descriptor */
typedef struct {
  uint32_t flvalsig;
  uint32_t flmap0;
  uint32_t flmap1;
  uint32_t flmap2;
  uint8_t  reserved[0xefc - 0x20];
  uint32_t flumap1;
} __attribute__((packed)) fdbar_t;

/* regions */
typedef struct {
  uint32_t flreg0;
  uint32_t flreg1;
  uint32_t flreg2;
  uint32_t flreg3;
  uint32_t flreg4;
} __attribute__((packed)) frba_t;

typedef struct {
  int base, limit, size;
} region_t;

static fdbar_t *find_fd(const uint8_t *image, int size)
{
  int i, found = 0;

  /* Scan for FD signature */
  for (i = 0; i <= (size - sizeof(fdbar_t)); i += 4) {
    if (*(uint32_t *) (image + i) == 0x0FF0A55A) {
      found = 1;
      break;// signature found.
    }
  }

  if (!found)
    return NULL;

  msg_ginfo("Found Flash Descriptor signature at 0x%08x\n", i);

  return (fdbar_t *) (image + i);
}

static region_t get_region(const frba_t *frba, int region_type)
{
  region_t region;
  region.base = 0, region.limit = 0, region.size = 0;

  switch (region_type) {
  case 0:
    region.base = (frba->flreg0 & 0x00000fff) << 12;
    region.limit = ((frba->flreg0 & 0x0fff0000) >> 4) | 0xfff;
    break;
  case 1:
    region.base = (frba->flreg1 & 0x00000fff) << 12;
    region.limit = ((frba->flreg1 & 0x0fff0000) >> 4) | 0xfff;
    break;
  case 2:
    region.base = (frba->flreg2 & 0x00000fff) << 12;
    region.limit = ((frba->flreg2 & 0x0fff0000) >> 4) | 0xfff;
    break;
  case 3:
    region.base = (frba->flreg3 & 0x00000fff) << 12;
    region.limit = ((frba->flreg3 & 0x0fff0000) >> 4) | 0xfff;
    break;
  case 4:
    region.base = (frba->flreg4 & 0x00000fff) << 12;
    region.limit = ((frba->flreg4 & 0x0fff0000) >> 4) | 0xfff;
    break;
  default:
    break;
  }

  region.size = region.limit - region.base + 1;

  return region;
}

int ifd_read_romlayout(const uint8_t *const oldcontents,
                       const uint8_t *const newcontents,
                       const unsigned flash_size,
                       romlayout_t *const entries,
                       int *const n_entries)
{
  static const char *regions[5] = {
    "Flash_Descriptor",
    "BIOS",
    "Intel_ME",
    "GbE",
    "Platform_Data"
  };

  const int max_entries = *n_entries;
  *n_entries = 0;

  const fdbar_t *const fdb_old = find_fd(oldcontents, flash_size);
  if (!fdb_old) {
    msg_gerr("No IFD found in old flash contents.\n");
    return 1;
  }
  const fdbar_t *const fdb_new = find_fd(newcontents, flash_size);
  if (!fdb_old) {
    msg_gerr("No IFD found in new flash contents.\n");
    return 1;
  }

  const frba_t *const fr_old = (frba_t *)(oldcontents + (((fdb_old->flmap0 >> 16) & 0xff) << 4));
  const frba_t *const fr_new = (frba_t *)(newcontents + (((fdb_new->flmap0 >> 16) & 0xff) << 4));
  int i;
  for (i = 0; i < 5; ++i) {
    const region_t reg_old = get_region(fr_old, i);
    const region_t reg_new = get_region(fr_new, i);
    if (reg_old.base != reg_new.base || reg_old.limit != reg_new.limit) {
      msg_gerr("Image '%s' doesn't match in old and new IFD, won't flash.\n",
               regions[i]);
      return 1;
    }
    if (reg_old.size <= 0)
      continue;

    if (*n_entries >= max_entries) {
      msg_gerr("Maximum number of ROM images (%i) in layout reached.\n",
               max_entries);
      return 1;
    }
    entries[*n_entries].start = reg_old.base;
    entries[*n_entries].end = reg_old.limit;
    snprintf(entries[*n_entries].name, sizeof(entries[*n_entries].name),
             "%s", regions[i]);
    msg_ginfo("Found flash region [%08x:%08x] %s\n", entries[*n_entries].start,
              entries[*n_entries].end, entries[*n_entries].name);
    ++*n_entries;
  }
  return 0;
}
