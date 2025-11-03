#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#define SWAP_BUFS(a, b) {unsigned char* temp = a; a = b; b = temp;}
#define NUM_BUCKETS(n) ((uint64_t)1 << (8 * n))

// Return size of file in bytes
size_t get_file_size_stat(const char* filename) {
    struct stat st;
    if (stat(filename, &st) == -1) {
        assert(1);
    }
    return st.st_size;
}

// Return the index corresponding to first N bytes of buf
uint64_t get_prefix_as_index(unsigned char* buf, uint64_t N) {
    uint64_t prefix = 0;
    for (int i = 0; i < N; i++) {
        prefix = (prefix << 8) | buf[i];
    }
    return prefix;
}

// Populate hist from buf, indexed by N bytes starting at byte_offset
void populate_histogram(unsigned char* buf, size_t buf_size, uint32_t* hist, uint32_t element_size, uint32_t byte_offset, uint64_t N) {
    memset(hist, 0, NUM_BUCKETS(N) * sizeof(uint32_t));

    for (size_t i = 0; i < buf_size/element_size; i++) {
        hist[get_prefix_as_index(buf + (i * element_size) + byte_offset, N)]++;
    }
}

// Bucket values of buf into partition as specified by hist, and return element offsets for indexing into partition
void construct_partition(uint32_t* hist, unsigned char* partition, unsigned char* buf, unsigned int buf_size, uint32_t* base_offsets, uint32_t* insert_offsets, int element_size, uint32_t byte_offset, uint64_t N) {
    uint64_t num_buckets = NUM_BUCKETS(N);
    memset(base_offsets, 0, num_buckets * sizeof(uint32_t));
    memset(insert_offsets, 0, num_buckets * sizeof(uint32_t));

    uint32_t current_offset = 0;
    for (size_t i = 0; i < num_buckets; i++) {
        base_offsets[i] = current_offset;
        insert_offsets[i] = current_offset;
        current_offset += hist[i];
    }

    for (uint32_t i = 0; i < buf_size/element_size; i++) {
        uint64_t prefix = get_prefix_as_index(buf+(i*element_size)+ byte_offset, N);
        uint32_t prefix_offset = insert_offsets[prefix];
        insert_offsets[prefix]++;
        memcpy(partition+(prefix_offset*element_size), buf+(i*element_size), element_size);
    }
}

// Swap n bytes of s1 and s2
void bytewise_swap(unsigned char* s1, unsigned char* s2, int n) {
    for (int i = 0; i < n; i++) {
        s1[i] = s1[i] ^ s2[i];
        s2[i] = s1[i] ^ s2[i];
        s1[i] = s1[i] ^ s2[i];
    }
}

// Gnome sort. Need I say more?
int gnome_sort(unsigned char* buf, unsigned int buf_size, unsigned int element_size) {
    int num_swaps = 0;
    uint32_t i = 0;
    uint32_t j = 1;
    while(1) {
        if (memcmp(buf+(i*element_size), buf+(j*element_size), element_size) <= 0) {
            i++;
            j++;
            if (j >= buf_size/element_size) {
                return num_swaps;
            }
        }
        else {
            num_swaps++;
            bytewise_swap(buf+(i*element_size), buf+(j*element_size), element_size);
            if (i > 0) {
                i--;
                j--;
            }
        }
    }
}

// thanks chatgpt for a slightly faster hex converter
void write_as_hex(unsigned char* s, unsigned int n, FILE* outfile) {
    static const char HEX[] = "0123456789abcdef";

    // Convert & flush in large chunks to cut syscall overhead.
    const size_t IN_CHUNK = 1u << 20;            // 1 MiB input per chunk
    char *obuf = (char *)malloc(2 * IN_CHUNK);   // temp output buffer (2 bytes per input byte)
    if (!obuf) { perror("malloc"); return; }

    size_t off = 0;
    while (off < n) {
        size_t m = n - off;
        if (m > IN_CHUNK) m = IN_CHUNK;

        char *p = obuf;
        const unsigned char *src = s + off;
        for (size_t i = 0; i < m; i++) {
            unsigned char b = src[i];
            *p++ = HEX[b >> 4];
            *p++ = HEX[b & 0x0F];
        }

        // Write the converted block in one go.
        if (fwrite(obuf, 1, 2 * m, outfile) != 2 * m) {
            perror("fwrite");
            free(obuf);
            return;
        }
        off += m;
    }

    fputc('\n', outfile);
    free(obuf);
}

unsigned int write_uniques(unsigned char* sorted, unsigned int sorted_size, unsigned int element_size,  FILE* outfile, int write_binary) {
    if (sorted_size > 0) {
        if (write_binary) {
            fwrite(sorted, element_size, 1, outfile);
        } else {
            write_as_hex(sorted, element_size, outfile);
        }
    }
    for (int i = 1; i < sorted_size/element_size; i++) {
        if (memcmp(sorted+(i*element_size), sorted+((i-1)*element_size), element_size) != 0) {
            if (write_binary) {
                fwrite(sorted+(i*element_size), element_size, 1, outfile);

            } else {
                write_as_hex(sorted+(i*element_size), element_size, outfile);
            }
        }
    }
}

// perform lsd radix on N bytes at a time for I iterations. Returns ptr to buffer filled with data, regardless of parity. buf_a if I is even, buf_b if odd. Expects input in buf_a.
char* ping_pong(unsigned char* buf_a, unsigned char* buf_b, size_t buf_size, uint32_t* histogram, uint32_t element_size, uint32_t* base_offsets, uint32_t* insert_offsets, unsigned int I, unsigned int N) {
    for (int i = 0; i < I; i++) {
        populate_histogram(buf_a, buf_size, histogram, element_size, (I - i - 1) * N, N);
        construct_partition(histogram, buf_b, buf_a, buf_size, base_offsets, insert_offsets, element_size, (I - i - 1) * N, N);
        SWAP_BUFS(buf_a, buf_b);
    }
    return buf_a;
}

typedef struct 
{
    char* buf_a;
    char* buf_b;
    uint32_t element_size;
    unsigned int I;
    unsigned int N;
    uint64_t* thread_partition_index;
    size_t* thread_partition_size;
} Shared_Data;

typedef struct
{
    int tid;
    const Shared_Data* shared_data;
} Thread_Data;


void* sort_thread_partition(void* arg) {
    Thread_Data* thread_data = (Thread_Data*)arg;
    const Shared_Data* shared_data = thread_data->shared_data;
    int tid = thread_data->tid;
    uint32_t element_size = shared_data->element_size;

    char* buf_a = shared_data->buf_a + (shared_data->thread_partition_index[tid] * element_size);
    char* buf_b = shared_data->buf_b + (shared_data->thread_partition_index[tid] * element_size);
    size_t buf_size = shared_data->thread_partition_size[tid] * element_size;
    unsigned int I = shared_data->I;
    unsigned int N = shared_data->N;

    uint64_t num_buckets = NUM_BUCKETS(N);

    uint32_t* histogram = calloc(num_buckets, sizeof(uint32_t));
    uint32_t* base_offsets = calloc(num_buckets, sizeof(uint32_t));
    uint32_t* insert_offsets = calloc(num_buckets, sizeof(uint32_t));

    char* live_buf = ping_pong(buf_a, buf_b, buf_size, histogram, element_size, base_offsets, insert_offsets, I, N);

    int swaps = gnome_sort(live_buf, buf_size, element_size);

    free(histogram);
    free(base_offsets);
    free(insert_offsets);

    return NULL;
} 

int main(int argc, char *argv[]) { // TODO: make some of these into options for more intuitive command typing
    if (argc != 8) {
        fprintf(stderr, "Usage: %s <input_file as raw bytes> <output_file> <element_size in bits> <bytes per iteration> <num iterations> <0: write hex | 1: write raw bytes> <num_threads>\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        fprintf(stderr, "Error opening input file\n");
        return 1;
    }

    FILE *out = fopen(argv[2], "w");
    if (!out) {
        fprintf(stderr, "Error opening output file\n");
        fclose(in);
        return 1;
    }

    size_t buf_size = (size_t)get_file_size_stat(argv[1]);
    int bits = atoi(argv[3]);
    if (bits % 8 != 0) {
        fprintf(stderr, "Element size must be a multiple of 8 bits\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    uint32_t element_size = (uint32_t)(bits/8);
    if(buf_size % element_size != 0) {
        fprintf(stderr, "File size must be a multiple of element size in bytes\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    int N = atoi(argv[4]);
    int I = atoi(argv[5]);

    uint64_t num_buckets = NUM_BUCKETS(N);

    if(N * I > element_size) {
        fprintf(stderr, "(num iterations * num bytes per iteration) must be less than element size in bytes\n");
        fclose(in);
        fclose(out);
        return 1; 
    }

    int write_binary = atoi(argv[6]);

    int num_threads = atoi(argv[7]);

    // use two buffers to perform iterative partitioning
    unsigned char* buf_a = calloc(buf_size, 1);
    unsigned char* buf_b = calloc(buf_size, 1);

    // reuse histogram and offsets for each iteration
    uint32_t* histogram = calloc(num_buckets, sizeof(uint32_t));
    uint32_t* base_offsets = calloc(num_buckets, sizeof(uint32_t));
    uint32_t* insert_offsets = calloc(num_buckets, sizeof(uint32_t));

    size_t bytes_read = fread(buf_a, 1, buf_size, in);
    assert(bytes_read == buf_size);

    populate_histogram(buf_a, buf_size, histogram, element_size, 0, N);
    construct_partition(histogram, buf_b, buf_a, buf_size, base_offsets, insert_offsets, element_size, 0, N);
    SWAP_BUFS(buf_a, buf_b); // live data ptr is now buf_a



    uint64_t* thread_partition_index = calloc(num_threads, sizeof(uint64_t));   // array of indexes into buf belonging to thread
    size_t* thread_partition_size = calloc(num_threads, sizeof(size_t));        // array of sizes of partition belonging to thread

    uint32_t target_size = (buf_size / element_size) / num_threads;         // optimal num of elements per thread
    uint64_t idx = 0;
    for (int i = 0; i < num_threads - 1; i++) {
        uint64_t starting_idx = idx;
        thread_partition_index[i] = base_offsets[idx];   // set beginning of this thread's partition
        uint32_t current_target = target_size * (i + 1);
        while (base_offsets[idx] < current_target) {
            idx++;
        }
        uint32_t rd = base_offsets[idx] - current_target;   // overfill amount if snap right
        uint32_t ld = current_target - base_offsets[idx-1]; // underfill amount if snap left
        assert(rd >= 0); assert(ld >= 0);
        if (ld < rd) {
            idx--;
        }
        thread_partition_size[i] = base_offsets[idx] - base_offsets[starting_idx];
    }
    uint64_t total_elems = buf_size / element_size;
    thread_partition_index[num_threads - 1] = base_offsets[idx];
    thread_partition_size[num_threads - 1]  = total_elems - base_offsets[idx]; 

    free(histogram);
    free(base_offsets);
    free(insert_offsets);

    Shared_Data shared_data = {.buf_a = buf_a, .buf_b = buf_b, .element_size = element_size, .I = I, .N = N, .thread_partition_index = thread_partition_index, .thread_partition_size = thread_partition_size};
    Thread_Data thread_data[num_threads];
    pthread_t threads[num_threads];

    for (int t = 0; t < num_threads; t++) {
        thread_data[t].tid = t;
        thread_data[t].shared_data = &shared_data;
        if (pthread_create(&threads[t], NULL, sort_thread_partition, &thread_data[t]) != 0) {
            perror("failed to create thread :(");
            exit(1);
        }
    }

    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }

    if (I % 2 != 0) {
        SWAP_BUFS(buf_a, buf_b);
    }

    write_uniques(buf_a, buf_size, element_size, out, write_binary);

    printf("Done!\n");

    free(buf_a);
    free(buf_b);

    fclose(in);
    fclose(out);
    return 0;
}

