#include <stdio.h>
#include <stdlib.h>

void write_as_hex(unsigned char* s, unsigned int n, FILE* outfile) {
    static const char HEX[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        unsigned char b = s[i];
        fputc(HEX[b >> 4], outfile);
        fputc(HEX[b & 0x0F], outfile);
    }
    fputc('\n', outfile);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <N>\n", argv[0]);
        return 1;
    }

    const char *input_filename = argv[1];
    unsigned int N = atoi(argv[2]);
    if (N == 0) {
        fprintf(stderr, "Error: N must be > 0\n");
        return 1;
    }

    FILE *in = fopen(input_filename, "rb");
    if (!in) {
        perror("Error opening input file");
        return 1;
    }

    FILE* out = fopen("unsorted", "w");

    unsigned char *buf = malloc(N);
    if (!buf) {
        perror("malloc failed");
        fclose(in);
        return 1;
    }

    while (1) {
        size_t read_bytes = fread(buf, 1, N, in);
        if (read_bytes == 0)
            break;
        write_as_hex(buf, (unsigned int)read_bytes, out);
    }

    free(buf);
    fclose(in);
    return 0;
}
