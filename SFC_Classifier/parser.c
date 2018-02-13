#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <arpa/inet.h>

#include "json.h"
#include "classifier.h"

int parse_match(json_value *value, struct sfc_rule *rule) {
	if (value == NULL || value->type != json_object)
		return -1;

	int length = value->u.object.length;
        for (int x = 0; x < length; x++) {
		json_value *obj = value->u.object.values[x].value;
		char *name = value->u.object.values[x].name;
		if (!strcmp("ip_dst", name) && obj->type == json_string) {
			if (inet_pton(AF_INET6, obj->u.string.ptr, &(rule->ip_dst)) != 1)
				return -1;
			rule->fields |= IP_DST;
		}
		else if (!strcmp("ip_src", name) && obj->type == json_string) {
			if (inet_pton(AF_INET6, obj->u.string.ptr, &(rule->ip_src)) != 1)
				return -1;
			rule->fields |= IP_SRC;
		}
		else if (!strcmp("proto", name) && obj->type == json_string) {
			if (!strcmp("TCP", obj->u.string.ptr))
				rule->proto = TCP;
			else if (!strcmp("UDP", obj->u.string.ptr))
				rule->proto = UDP;
			else if (!strcmp("ICMP", obj->u.string.ptr))
				rule->proto = ICMP;
			else
				return -1;

			rule->fields |= PROTO;
		}
		else if (!strcmp("dport", name) && obj->type == json_integer) {
			rule->dport = obj->u.integer & 65535;
			rule->fields |= DPORT;
		}
		else if (!strcmp("sport", name) && obj->type == json_integer) {
			rule->sport = obj->u.integer & 65535;
			rule->fields |= SPORT;
		}
		else if (!strcmp("transport_flags", name) && obj->type == json_integer) {
			rule->transport_flags = obj->u.integer & 255;
			rule->fields |= TRANS_FLAGS;
		}
		else {
			printf("Unknown parameter: %s\n", value->u.object.values[x].name);
			return -1;
		}
        }

	return 0;
}

int parse_srh(json_value *value, struct sfc_rule *rule) {
	rule->srh.type = 4;
	rule->srh.nexthdr = 0;
	rule->srh.flags = 0;
	rule->srh.tag = 0;

	if (value == NULL || value->type != json_object)
		return -1;

	if (value->u.object.length < 1 || value->u.object.length > 2)
		return -1;

	json_value *obj = value->u.object.values[0].value;
	char *name = value->u.object.values[0].name;
	int nb_segs = obj->u.array.length;
	if (!strcmp("segments", name) && obj->type == json_array) {
		for(int i=0; i < obj->u.array.length; i++) {
			json_value *seg = obj->u.array.values[i];
			if (seg->type != json_string)
				return -1;
			if (inet_pton(AF_INET6, seg->u.string.ptr, &(rule->srh.segments[i])) != 1)
				return -1;
			rule->srh.hdrlen += 2;
		}
	}
	else {
		printf("Unknown parameter: %s (needs to be 'segments')\n", name);
		return -1;
	}

	rule->srh.first_segment = nb_segs-1;
	rule->srh.segments_left = nb_segs-1;

	if (value->u.object.length == 1)
		return 0;

	obj = value->u.object.values[1].value;
	name = value->u.object.values[1].name;
	struct sr6_tlv *srh_tlv = (struct sr6_tlv *)(&rule->srh.segments[nb_segs]);
	int tlv_len = 0;

	if (!strcmp("tlvs", name) && obj->type == json_array) {
		for(int i=0; i < obj->u.array.length; i++) {
			json_value *tlv = obj->u.array.values[i];
			if (tlv->u.object.length != 3)
				return -1;

			for (int i=0; i < 3; i++) {
				if (!strcmp(tlv->u.object.values[i].name, "type") && tlv->u.object.values[i].value->type == json_integer) {
					srh_tlv->type = tlv->u.object.values[i].value->u.integer;
				}
				else if (!strcmp(tlv->u.object.values[i].name, "length") && tlv->u.object.values[i].value->type == json_integer) {
					srh_tlv->len = tlv->u.object.values[i].value->u.integer;
				}
				else if (!strcmp(tlv->u.object.values[i].name, "value") && tlv->u.object.values[i].value->type == json_string) {
					char *src = tlv->u.object.values[i].value->u.string.ptr;
					char *dst = (char *) srh_tlv->value;
					for (size_t count = 0; count < strlen(src)/2; count++) {
						sscanf(src+count*2, "%2hhx", dst+count);
					}
				}
				else {
					return -1;
				}
			}
			tlv_len += 2 + srh_tlv->len;
			srh_tlv = (struct sr6_tlv *) ((char *) srh_tlv + tlv_len);
		}

		rule->srh.hdrlen += (tlv_len >> 3);
	}
	else {
		printf("Unknown parameter: %s (needs to be 'tlvs')\n", name);
		return -1;
	}

	return 0;
}

int parse_rule(json_value *value, struct sfc_rule *rule)
{
	if (value == NULL || value->type != json_object)
		return -1;

	int length = value->u.object.length;
	json_value *match, *srh;
        for (int x = 0; x < length; x++) {
		if (!strcmp("match", value->u.object.values[x].name))
			match = value->u.object.values[x].value;
		else if (!strcmp("srh", value->u.object.values[x].name))
			srh = value->u.object.values[x].value;
        }

	if (srh == NULL || match == NULL)
		return -1;

	if (parse_match(match, rule) < 0)
		return -1;
	if (parse_srh(srh, rule) < 0)
		return -1;

	return 0;
}

void *parse_rules(int argc, char *argv[], int *nb_rules)
{
	char* filename;
        FILE *fp;
        struct stat filestatus;
        int file_size;
        char* file_contents;
        json_char* json;
        json_value* value;

        if (argc != 2) {
                fprintf(stderr, "%s <file_json>\n", argv[0]);
		exit(1);
        }
        filename = argv[1];

        if ( stat(filename, &filestatus) != 0) {
                fprintf(stderr, "File %s not found\n", filename);
		exit(1);
        }
        file_size = filestatus.st_size;
        file_contents = (char*)malloc(filestatus.st_size);
        if ( file_contents == NULL) {
                fprintf(stderr, "Memory error: unable to allocate %d bytes\n", file_size);
		exit(1);
        }

        fp = fopen(filename, "rt");
        if (fp == NULL) {
                fprintf(stderr, "Unable to open %s\n", filename);
                fclose(fp);
                free(file_contents);
		exit(1);
        }
        if ( fread(file_contents, file_size, 1, fp) != 1 ) {
                fprintf(stderr, "Unable t read content of %s\n", filename);
                fclose(fp);
                free(file_contents);
		exit(1);
        }
        fclose(fp);

        json = (json_char*)file_contents;
        value = json_parse(json,file_size);

        if (value == NULL || value->type != json_array)
		goto parse_err;


	*nb_rules = value->u.array.length;
	struct sfc_rule *rules = malloc(sizeof(struct sfc_rule) * *nb_rules);
	if (rules == NULL) {
		fprintf(stderr, "Memory error");
		goto err;
	}

        for (int i = 0; i < *nb_rules; i++) {
		int r = parse_rule(value->u.array.values[i], (struct sfc_rule *)(rules + i));
		if (r < 0)
			goto parse_err;
        }

        for (int i = 0; i < *nb_rules; i++) {
		struct sfc_rule *rule = (struct sfc_rule *)(rules + i);
		for(int i=0; i < (rule->srh.hdrlen + 1) << 3; i++) {
			unsigned char x = *(((char *)&rule->srh)+i);
			printf("%02X ", x);
			if ((i+1) % 16 == 0)
				printf("\n");
		}
		printf("\n");
	}


        json_value_free(value);
        free(file_contents);
        return (void *)rules;

parse_err:
	fprintf(stderr, "Unable to parse data\n");
err:
	free(rules);
	free(file_contents);
	exit(1);

}
