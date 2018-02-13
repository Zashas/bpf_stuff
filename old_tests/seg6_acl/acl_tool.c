/*-
 *    GNU GENERAL PUBLIC LICENSE, Version 2
 *
 *    Copyright (C) 2017, 6WIND S.A.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* This program contains the code needed to initialize an eBPF map, the XFSM
 * map, in order to run the token bucket proof-of-concept stateful application.
 * The state map starts empty.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Const and struct definitions */


/* Some helpers */

int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
  return syscall(__NR_bpf, cmd, attr, size);
#else
  fprintf(stderr, "No bpf syscall, kernel headers too old?\n");
  errno = ENOSYS;
  return -1;
#endif
}

__u64 bpf_ptr_to_u64(const void *ptr)
{
  return (__u64) (unsigned long) ptr;
}

int bpf_update_elem(int fd, void *key, void *value, u64 flags)
{
  union bpf_attr attr = {};
  attr.map_fd = fd;
  attr.key    = bpf_ptr_to_u64(key);
  attr.value  = bpf_ptr_to_u64(value);;
  attr.flags  = flags;

  static int nb = 0;
  nb++;
  int ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  if (ret < 0) {
    fprintf(stderr, "Map update #%d failed: %s\n", nb, strerror(errno));
  }
  return ret;
}

/* Main function */

int main (int argc, char *argv[]) {

    int update_what = 0;
    u64 tag = 0;
    struct in6_addr ip;
    if (argc > 2) {
        if(!strcmp(argv[1], "tag")) {
            tag = atoi(argv[2]);        
            update_what = 1;
        }
        else if(!strcmp(argv[1], "seg")) {
            const char *ip6str = "::2";

            if (inet_pton(AF_INET6, argv[2], &ip) != 1) {
                printf("incorrect ip address\n");
                return 0;
            }
            update_what = 2;
        }
        else {
            printf("incorrect parameter\n");
            return 0;
        }
    }
    else {
        printf("not enough parameters\n");
        return 0;
    }

  union bpf_attr attr_obj = {};
  int map_fd;

  char *path = "/sys/fs/bpf/tc/globals/map_acl";


  attr_obj.map_fd = 0;
  attr_obj.pathname = bpf_ptr_to_u64(path);
  map_fd = bpf(BPF_OBJ_GET, &attr_obj, sizeof(attr_obj));
  if (map_fd <= 0) {
    fprintf(stderr, "Getting map failed: %s\n", strerror(errno));
    return -1;
  }

  if (update_what == 1) {
      u32 key = 0;
      bpf_update_elem(map_fd, &key, &tag, BPF_ANY);
  }
  else if (update_what == 2) {
      u64 low, high;
      memcpy(&high, ip.s6_addr, sizeof(high));
      memcpy(&low, ip.s6_addr+8, sizeof(low));

      u32 key = 1;
      bpf_update_elem(map_fd, &key, &high, BPF_ANY);
      key = 2;
      bpf_update_elem(map_fd, &key, &low, BPF_ANY);
  }

  return 0;
}
