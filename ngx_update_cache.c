/**
 * This program updates Nginx cache objects on version 1.6 format to version 1.8 format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static const int width = 15;
static u_char  ngx_http_file_cache_key[] = { '\n', 'K', 'E', 'Y', ':', ' ' };
static int verbose = 0;

#define NGX_HTTP_CACHE_KEY_LEN       16
#define NGX_HTTP_CACHE_ETAG_LEN      42
#define NGX_HTTP_CACHE_VARY_LEN      42

#define ngx_memcpy memcpy
#define ngx_memzero bzero

typedef unsigned int ngx_uint_t;

typedef struct {
    ngx_uint_t                       version;
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
    u_char                           etag_len;
    u_char                           etag[NGX_HTTP_CACHE_ETAG_LEN];
    u_char                           vary_len;
    u_char                           vary[NGX_HTTP_CACHE_VARY_LEN];
    u_char                           variant[NGX_HTTP_CACHE_KEY_LEN];
} ngx_18_t;

typedef struct {
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
} ngx_16_t;

static const size_t header_offset = sizeof(ngx_18_t) - sizeof(ngx_16_t);

typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d;
    u_char    buffer[64];
} ngx_md5_t;


void ngx_md5_init(ngx_md5_t *ctx);
void ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t size);
void ngx_md5_final(u_char result[16], ngx_md5_t *ctx);

static const u_char *ngx_md5_body(ngx_md5_t *ctx, const u_char *data,
    size_t size);


void
ngx_md5_init(ngx_md5_t *ctx)
{
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;

    ctx->bytes = 0;
}


void
ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t size)
{
    size_t  used, free;

    used = (size_t) (ctx->bytes & 0x3f);
    ctx->bytes += size;

    if (used) {
        free = 64 - used;

        if (size < free) {
            ngx_memcpy(&ctx->buffer[used], data, size);
            return;
        }

        ngx_memcpy(&ctx->buffer[used], data, free);
        data = (u_char *) data + free;
        size -= free;
        (void) ngx_md5_body(ctx, ctx->buffer, 64);
    }

    if (size >= 64) {
        data = ngx_md5_body(ctx, data, size & ~(size_t) 0x3f);
        size &= 0x3f;
    }

    ngx_memcpy(ctx->buffer, data, size);
}


void
ngx_md5_final(u_char result[16], ngx_md5_t *ctx)
{
    size_t  used, free;

    used = (size_t) (ctx->bytes & 0x3f);

    ctx->buffer[used++] = 0x80;

    free = 64 - used;

    if (free < 8) {
        ngx_memzero(&ctx->buffer[used], free);
        (void) ngx_md5_body(ctx, ctx->buffer, 64);
        used = 0;
        free = 64;
    }

    ngx_memzero(&ctx->buffer[used], free - 8);

    ctx->bytes <<= 3;
    ctx->buffer[56] = (u_char) ctx->bytes;
    ctx->buffer[57] = (u_char) (ctx->bytes >> 8);
    ctx->buffer[58] = (u_char) (ctx->bytes >> 16);
    ctx->buffer[59] = (u_char) (ctx->bytes >> 24);
    ctx->buffer[60] = (u_char) (ctx->bytes >> 32);
    ctx->buffer[61] = (u_char) (ctx->bytes >> 40);
    ctx->buffer[62] = (u_char) (ctx->bytes >> 48);
    ctx->buffer[63] = (u_char) (ctx->bytes >> 56);

    (void) ngx_md5_body(ctx, ctx->buffer, 64);

    result[0] = (u_char) ctx->a;
    result[1] = (u_char) (ctx->a >> 8);
    result[2] = (u_char) (ctx->a >> 16);
    result[3] = (u_char) (ctx->a >> 24);
    result[4] = (u_char) ctx->b;
    result[5] = (u_char) (ctx->b >> 8);
    result[6] = (u_char) (ctx->b >> 16);
    result[7] = (u_char) (ctx->b >> 24);
    result[8] = (u_char) ctx->c;
    result[9] = (u_char) (ctx->c >> 8);
    result[10] = (u_char) (ctx->c >> 16);
    result[11] = (u_char) (ctx->c >> 24);
    result[12] = (u_char) ctx->d;
    result[13] = (u_char) (ctx->d >> 8);
    result[14] = (u_char) (ctx->d >> 16);
    result[15] = (u_char) (ctx->d >> 24);

    ngx_memzero(ctx, sizeof(*ctx));
}


/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in
 * Colin Plumb's implementation.
 */

#define F(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)  ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)  ((x) ^ (y) ^ (z))
#define I(x, y, z)  ((y) ^ ((x) | ~(z)))

/*
 * The MD5 transformation for all four rounds.
 */

#define STEP(f, a, b, c, d, x, t, s)                                          \
    (a) += f((b), (c), (d)) + (x) + (t);                                      \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));                \
    (a) += (b)

#define SET(n)                                                                \
    (block[n] =                                                               \
    (uint32_t) p[n * 4] |                                                     \
    ((uint32_t) p[n * 4 + 1] << 8) |                                          \
    ((uint32_t) p[n * 4 + 2] << 16) |                                         \
    ((uint32_t) p[n * 4 + 3] << 24))

#define GET(n)      block[n]

/*
 * This processes one or more 64-byte data blocks, but does not update
 * the bit counters.  There are no alignment requirements.
 */

static const u_char *
ngx_md5_body(ngx_md5_t *ctx, const u_char *data, size_t size)
{
    uint32_t       a, b, c, d;
    uint32_t       saved_a, saved_b, saved_c, saved_d;
    const u_char  *p;
    uint32_t       block[16];

    p = data;

    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        /* Round 1 */

        STEP(F, a, b, c, d, SET(0),  0xd76aa478, 7);
        STEP(F, d, a, b, c, SET(1),  0xe8c7b756, 12);
        STEP(F, c, d, a, b, SET(2),  0x242070db, 17);
        STEP(F, b, c, d, a, SET(3),  0xc1bdceee, 22);
        STEP(F, a, b, c, d, SET(4),  0xf57c0faf, 7);
        STEP(F, d, a, b, c, SET(5),  0x4787c62a, 12);
        STEP(F, c, d, a, b, SET(6),  0xa8304613, 17);
        STEP(F, b, c, d, a, SET(7),  0xfd469501, 22);
        STEP(F, a, b, c, d, SET(8),  0x698098d8, 7);
        STEP(F, d, a, b, c, SET(9),  0x8b44f7af, 12);
        STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17);
        STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22);
        STEP(F, a, b, c, d, SET(12), 0x6b901122, 7);
        STEP(F, d, a, b, c, SET(13), 0xfd987193, 12);
        STEP(F, c, d, a, b, SET(14), 0xa679438e, 17);
        STEP(F, b, c, d, a, SET(15), 0x49b40821, 22);

        /* Round 2 */

        STEP(G, a, b, c, d, GET(1),  0xf61e2562, 5);
        STEP(G, d, a, b, c, GET(6),  0xc040b340, 9);
        STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14);
        STEP(G, b, c, d, a, GET(0),  0xe9b6c7aa, 20);
        STEP(G, a, b, c, d, GET(5),  0xd62f105d, 5);
        STEP(G, d, a, b, c, GET(10), 0x02441453, 9);
        STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14);
        STEP(G, b, c, d, a, GET(4),  0xe7d3fbc8, 20);
        STEP(G, a, b, c, d, GET(9),  0x21e1cde6, 5);
        STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9);
        STEP(G, c, d, a, b, GET(3),  0xf4d50d87, 14);
        STEP(G, b, c, d, a, GET(8),  0x455a14ed, 20);
        STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5);
        STEP(G, d, a, b, c, GET(2),  0xfcefa3f8, 9);
        STEP(G, c, d, a, b, GET(7),  0x676f02d9, 14);
        STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20);

        /* Round 3 */

        STEP(H, a, b, c, d, GET(5),  0xfffa3942, 4);
        STEP(H, d, a, b, c, GET(8),  0x8771f681, 11);
        STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16);
        STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23);
        STEP(H, a, b, c, d, GET(1),  0xa4beea44, 4);
        STEP(H, d, a, b, c, GET(4),  0x4bdecfa9, 11);
        STEP(H, c, d, a, b, GET(7),  0xf6bb4b60, 16);
        STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23);
        STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4);
        STEP(H, d, a, b, c, GET(0),  0xeaa127fa, 11);
        STEP(H, c, d, a, b, GET(3),  0xd4ef3085, 16);
        STEP(H, b, c, d, a, GET(6),  0x04881d05, 23);
        STEP(H, a, b, c, d, GET(9),  0xd9d4d039, 4);
        STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11);
        STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16);
        STEP(H, b, c, d, a, GET(2),  0xc4ac5665, 23);

        /* Round 4 */

        STEP(I, a, b, c, d, GET(0),  0xf4292244, 6);
        STEP(I, d, a, b, c, GET(7),  0x432aff97, 10);
        STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15);
        STEP(I, b, c, d, a, GET(5),  0xfc93a039, 21);
        STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6);
        STEP(I, d, a, b, c, GET(3),  0x8f0ccc92, 10);
        STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15);
        STEP(I, b, c, d, a, GET(1),  0x85845dd1, 21);
        STEP(I, a, b, c, d, GET(8),  0x6fa87e4f, 6);
        STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10);
        STEP(I, c, d, a, b, GET(6),  0xa3014314, 15);
        STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21);
        STEP(I, a, b, c, d, GET(4),  0xf7537e82, 6);
        STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10);
        STEP(I, c, d, a, b, GET(2),  0x2ad7d2bb, 15);
        STEP(I, b, c, d, a, GET(9),  0xeb86d391, 21);

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        p += 64;

    } while (size -= 64);

    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;

    return p;
}

static inline void
print_key(char *buf, size_t offset) {
	static char tmp_key[32 * 1024];
    char *ptr = buf + offset + 6;
    char *nl = strchr(ptr, '\n');

    if (! nl ) {
        printf("%*s: ** Invalid **\n", width, "Key");
        return;
    }

    memcpy(tmp_key, ptr, nl - ptr);
    tmp_key[nl - ptr - 1] = '\0';

    printf("%*s: %s\n\n", width, "Key", tmp_key);
}

static inline void
print_cache_header_18(char *buf)
{
   ngx_18_t * cache_header = (ngx_18_t *) buf;

   printf("Nginx 1.8 Cache object:\n");
   printf("%*s: %u\n", width, "Version", cache_header->version);
   printf("%*s: %-22lu %s", width, "ValidSec", cache_header->valid_sec, ctime(&cache_header->valid_sec));
   printf("%*s: %-22ld %s", width, "LastMod", cache_header->last_modified, ctime(&cache_header->last_modified));
   printf("%*s: %-22lu %s", width, "Date", cache_header->date, ctime(&cache_header->date));
   printf("%*s: %u\n", width, "CRC-32", cache_header->crc32);
   printf("%*s: %u\n", width, "ValidMSec", cache_header->valid_msec);
   printf("%*s: %u\n", width, "HeaderStart", cache_header->header_start);
   printf("%*s: %u\n", width, "BodyStart", cache_header->body_start);
   printf("%*s: %u\n", width, "ETagLen", cache_header->etag_len);
   printf("%*s: %s\n", width, "ETag", cache_header->etag);
   printf("%*s: %u\n", width, "VaryLen", cache_header->vary_len);
   printf("%*s: %s\n", width, "Vary", cache_header->vary);
   //printf("%*s: %s\n", width, "Variant", cache_header->variant);

   print_key(buf, sizeof(ngx_18_t));
}

static inline void
print_cache_header_16(char *buf)
{
   ngx_16_t * cache_header = (ngx_16_t *) buf;

   printf("Nginx 1.6 Cache object:\n");
   printf("%*s: %-22lu %s", width, "ValidSec", cache_header->valid_sec, ctime(&cache_header->valid_sec));
   printf("%*s: %-22ld %s", width, "LastMod", cache_header->last_modified, ctime(&cache_header->last_modified));
   printf("%*s: %-22lu %s", width, "Date", cache_header->date, ctime(&cache_header->date));
   printf("%*s: %u\n", width, "CRC-32", cache_header->crc32);
   printf("%*s: %u\n", width, "ValidMSec", cache_header->valid_msec);
   printf("%*s: %u\n", width, "HeaderStart", cache_header->header_start);
   printf("%*s: %u\n", width, "BodyStart", cache_header->body_start);

   print_key(buf, sizeof(ngx_16_t));
}

static inline void
print_cache_header(const char *fname, char *buf, size_t sz_buf)
{
    char *key;
    char *ptr = buf;

    for (   key=memchr(ptr, '\n', sz_buf);
            key;
            ptr=key + 1, key=memchr(ptr, '\n', sz_buf)   )
    {
        if ( strncasecmp(key + 1, "key: ", 5) == 0 )
            break;
    }

    if (! key ) {
        fprintf(stderr, "Invalid cache file: %s\n", fname);
        return;
    }

    size_t key_offset = key - buf;

    if ( key_offset == sizeof(ngx_18_t) ) {
        return print_cache_header_18(buf);
    } else if ( key_offset == sizeof(ngx_16_t) ) {
        return print_cache_header_16(buf);
    } else {
        fprintf(stderr, "Invalid cache file: %s\n", fname);
    }
}



static inline int
is_v18(const char *fname, char *buf, size_t sz_buf)
{
    char *key;
    char *ptr = buf;

    for (   key=memchr(ptr, ngx_http_file_cache_key[0], sz_buf);
            key && (ptr - buf) < 4096;
            ptr=key + 1, key=memchr(ptr, ngx_http_file_cache_key[0], sz_buf)   )
    {
        int i;
    	for (i=1; i<6; ++i)
    		if ( *(key + i) != ngx_http_file_cache_key[i] )
    			break;
        if (i==6) break;
    }

    size_t key_offset;

    if (! key ) {
        fprintf(stderr, "Invalid cache file: %s\n", fname);
        return 1;
    }

    key_offset = key - buf;

    if ( key_offset == sizeof(ngx_18_t) ) {
        return 1;
    } else if ( key_offset == sizeof(ngx_16_t) ) {
        return 0;
    } else {
        fprintf(stderr, "Invalid cache file: %s\n", fname);
    }

    return 1;
}

static inline void
copy_header(const char *header, size_t sz_header, char *out, char *buf, size_t sentinel)
{
	char   *ptr;
	char   *header_end;

	for (ptr=buf; (size_t)(ptr - buf) < sentinel; ptr=strchr(ptr, '\n') + 1) {
		if ( strncasecmp(ptr, header, sz_header) == 0 ) {
			header_end = strchr(ptr + sz_header, '\n');
			if ( !header_end || (size_t)(header_end - buf) > sentinel ) {
				break;
			}

			if ( *(header_end - 1) == '\r' )
				--header_end;

			ptr += sz_header;

			while ( *ptr == ':' || *ptr == ' ' )
				++ptr;

			memcpy(out, ptr, header_end - ptr);
			out[header_end - ptr] = '\0';
			return;
		}
	}

	*out = '\0';
}

static inline int
parse_etag(ngx_18_t *new_header, char *buf) {
	char    etag[256];
	size_t  sentinel = new_header->body_start - new_header->header_start;

	copy_header("ETag", 4, etag, buf, sentinel);
	memset(new_header->etag, 0, NGX_HTTP_CACHE_ETAG_LEN);

	if ( *etag == '\0' ) {
		new_header->etag_len = 0;
		return 0;
	}

	new_header->etag_len = strlen(etag);
	strcpy((char *) new_header->etag, etag);

	return 0;
}

static inline int
parse_md5(char *key, size_t sz_key, u_char *out)
{
	ngx_md5_t          md5;

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, key, sz_key);
	ngx_md5_final(out, &md5);

	return 0;
}

static inline int
update_file(const char *fname)
{
    int  fd, fd_new = -1;
    int  rc;
    char buf[4096];
    int  parsing_header = 1;
    char dir[256];
    // char tmp_fname[] = "back_to_the_future.XXXXXX";
    char tmp_fname[40];

    ngx_16_t *old_header;
    ngx_18_t  new_header = { .version = 3 };

    char *key, *key_end;

    if ( (fd=open(fname, O_RDONLY)) < 0 ) {
        fprintf(stderr, "Could not open: %s. ", fname);
        perror("Reason");
        return 2;
    }

    while ( (rc=read(fd, &buf, sizeof(buf))) > 0 ) {
    	if ( parsing_header ) {
		    if ( is_v18(fname, buf, sizeof(buf)) ) {
		    	close(fd);
		    	if ( verbose ) printf("File [%s] is already on version 1.8.\n", fname);
		    	return 0;
		    }

		    old_header = (ngx_16_t *) buf;
		    if ( verbose ) {
		    	printf("Parsing: [%s]:\n", fname);
		    	print_cache_header_16(buf);
		    }

		    new_header.valid_sec = old_header->valid_sec;
		    new_header.last_modified = old_header->last_modified;
		    new_header.date = old_header->date;
		    new_header.crc32 = old_header->crc32;
		    new_header.valid_msec = old_header->valid_msec;
		    new_header.header_start = old_header->header_start + header_offset;
		    new_header.body_start = old_header->body_start + header_offset;

		    key = buf + sizeof(ngx_16_t) + sizeof(ngx_http_file_cache_key);
		    key_end = strchr(key, '\n');

            new_header.vary_len = 0;
            memset(&new_header.vary, 0, NGX_HTTP_CACHE_VARY_LEN);
            memset(&new_header.variant, 0, NGX_HTTP_CACHE_KEY_LEN);

		    if ( parse_etag(&new_header, buf + old_header->header_start) )
		    {
		    	fprintf(stderr, "Error while parsing file: %s\n", fname);
		    	close(fd);
		    	return 5;
		    }

            char *sep = strrchr(fname, '/');
            strncpy(dir, fname, sep - fname);
            dir[sep - fname] = '\0';
            strcpy(tmp_fname, ++sep);
            strncat(tmp_fname, ".XXXXXX", sizeof(tmp_fname));
            tmp_fname[sizeof(tmp_fname)-1] = '\0';

            if ( chdir(dir) != 0 ) {
                fprintf(stderr, "Could not enter directory [%s] for processing.", dir);
                perror("Reason");
                close(fd);
                return 6;
            }

		    if ( (fd_new=mkstemp(tmp_fname)) < 0 ) {
		    	fprintf(stderr, "Could not open tmp file [%s] for processing: %s. ", tmp_fname, fname);
		    	perror("Reason");
		    	close(fd);
		    	return 7;
		    }

		    if (   write(fd_new, &new_header, sizeof(new_header)) < 0 ||
		    	   write(fd_new, buf + sizeof(ngx_16_t), rc - sizeof(ngx_16_t)) < 0   )
		    {
		    	fprintf(stderr, "Could not write tmp file [%s] for processing: %s. ", tmp_fname, fname);
		    	perror("Reason");
		    	close(fd);
		    	return 8;
		    }

		    parsing_header = 0;
    	} else {
			write(fd_new, buf, sizeof(buf));
    	}
    }

    if ( rc < 0 ) {
        fprintf(stderr, "Could not read: %s. ", fname);
        perror("Reason");
        return 3;
    }

    if ( fd_new != -1 ) {
        struct stat fsb;
        fstat(fd, &fsb);
        close(fd);
    	close(fd_new);

    	if ( rename(tmp_fname, fname) != 0 ) {
            fprintf(stderr, "Could not move updated version of: %s. ", fname);
            perror("Reason");
            return 9;
        }

        if ( chown(fname, fsb.st_uid, fsb.st_gid) != 0 ) {
            fprintf(stderr, "Could not move set owner of file: %s to %u:%u. ", fname, fsb.st_uid, fsb.st_gid);
            perror("Reason");
            return 10;
        }
    } else close(fd);

    return 0;
}

int main(int argc, const char *argv[])
{
    int rc;

	for (int i=1; i<argc; ++i) {
		if ( strlen(argv[i]) != 2 )
			continue;
		if ( argv[i][0] == '-' && argv[i][1] == 'v' ) {
			verbose = 1;
			for (int j=i+1; j<argc; ++j)
				argv[j-1] = argv[j];
			argc -= 1;
			break;
		}
	}

    if ( argc < 2 ) {
        fprintf(stderr, "Usage: %s [-v] <file>\n", argv[0]);
        return 1;
    }

    for (int i=1; i<argc; ++i)
        if ( (rc=update_file(argv[i])) != 0 )
            return rc;

    return 0;
}
