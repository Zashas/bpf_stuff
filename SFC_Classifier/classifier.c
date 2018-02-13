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

#include "classifier.h"
#include "parser.h"

/*typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t uint32_t;
typedef uint64_t u64;*/

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

int bpf_update_elem(int fd, void *key, void *value, uint64_t flags)
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

int main (int argc, char *argv[])
{
	union bpf_attr attr_obj = {};
	int map_fd[2];

	char *map_paths[] = {"/sys/fs/bpf/ip/globals/map_rules", "/sys/fs/bpf/ip/globals/map_rules_nb"};


	for(int i=0; i < sizeof(map_fd)/sizeof(int); i++) {
		attr_obj.map_fd = 0;
		attr_obj.pathname = bpf_ptr_to_u64(map_paths[i]);
		map_fd[i] = bpf(BPF_OBJ_GET, &attr_obj, sizeof(attr_obj));
		if (map_fd[i] <= 0) {
			fprintf(stderr, "Fetching map failed: %s\n", strerror(errno));
			return -1;
		}
	}

	int nb_rules;
	struct sfc_rule *rules = (struct sfc_rule *)parse_rules(argc, argv, &nb_rules);

	printf("nb rules: %d\n", nb_rules);
	uint32_t key = 0;
	bpf_update_elem(map_fd[1], &key, &nb_rules, BPF_ANY);
	for(int i=0; i < nb_rules; i++) {
		struct sfc_rule *r = (struct sfc_rule*) (rules+i);
		printf("%p hdrlen:%d\n",r,r->srh.hdrlen); 
		bpf_update_elem(map_fd[0], &i, rules+i, BPF_ANY);
	}

	free(rules);
	return 0;
}
