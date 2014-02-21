#include <stdio.h>
#include <getopt.h>

int encode(unsigned int type, int lenient, int forward, FILE *in, FILE *out) {
	int res = 1;
	unsigned char buf[0xffff];
	unsigned char hdr[4];
	size_t len;
	int count = 0;

	if (in == NULL) in = stdin;
	if (out == NULL) out = stdout;

	while (1) {
		len = fread(buf, 1, sizeof(buf), in);

		if (len == 0 && count > 0) break;
		count++;

		/* TLV 18? */
		if (type > 0x1f || len > 0xff) {
			*hdr = 0x80 | (lenient * 0x40) | (forward * 0x20) | (type >> 8);
			*(hdr + 1) = type & 0xff;
			*(hdr + 2) = len >> 8;
			*(hdr + 3) = len & 0xff;
			fwrite(hdr, 1, 4, out);
		} else {
			*hdr = 0x00 | (lenient * 0x40) | (forward * 0x20) | (type);
			*(hdr + 1) = len & 0xff;
			fwrite(hdr, 1, 2, out);
		}

		fwrite(buf, 1, len, out);
	}

cleanup:

	return res;
}

int main(int argc, char **argv) {
	int res = 1;
	int c;
	int lenient = 0;
	int forward = 0;
	FILE *in = NULL;
	FILE *out = NULL;
	unsigned int type;
	char *tail = NULL;

	while ((c = getopt(argc, argv, "LFt:i:o:")) != -1) {
		switch (c) {
			case 'L':
				lenient = 1;
				break;
			case 'F':
				forward = 1;
				break;
			case 't':
				type = strtol(optarg, &tail, 0);
				if (*tail != 0) {
					fprintf(stderr, "Bad numeric type: '%s'", optarg);
					goto cleanup;
				}
				if (type > 0x1fff) {
					fprintf(stderr, "Type value too great (> 0x1fff)");
					goto cleanup;
				}
				break;
			case 'i':
				in = fopen(optarg, "rb");
				if (in == NULL) {
					fprintf(stderr, "Unable to open input file '%s'\n", optarg);
					goto cleanup;
				}
				break;
			case 'o':
				out = fopen(optarg, "wb");
				if (in == NULL) {
					fprintf(stderr, "Unable to open output file '%s'\n", optarg);
					goto cleanup;
				}
				break;
		}
	}

	res = encode(type, lenient, forward, in, out);

cleanup:

	if (in != NULL) fclose(in);
	if (out != NULL) fclose(out);

	return res;
}
