/**
 * This program prints information about Nginx's cache files, on versions 1.6 or 1.8.
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static const int width = 15;

#define NGX_HTTP_CACHE_KEY_LEN       16
#define NGX_HTTP_CACHE_ETAG_LEN      42
#define NGX_HTTP_CACHE_VARY_LEN      42

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

static inline void
print_key(char *buf, size_t offset) {
    char *ptr = buf + offset + 6;
    char *nl = strchr(ptr, '\n');

    if (! nl ) {
        printf("%*s: ** Invalid **\n", width, "Key");
        return;
    }

    *nl = '\0';

    printf("%*s: %-*s\n\n", width, "Key", (int) (nl - ptr), ptr);
}

static inline const char *
print_bin(u_char *bin, char *txt, size_t sz_bin)
{
  char   *ptr = txt;
  size_t  i;

  for (i=0; i < sz_bin; ++i) {
    sprintf(ptr, "%02x ", (int) bin[i]);
    ptr += 3;
  }

  txt[sz_bin * 3] = '\0';

  return txt;
}

static inline void
print_cache_header_18(char *buf)
{
  char variant[(NGX_HTTP_CACHE_KEY_LEN * 3) + 1];
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
  printf("%*s: %s\n", width, "Variant", print_bin(cache_header->variant, variant, NGX_HTTP_CACHE_KEY_LEN));

  print_key(buf, sizeof(ngx_18_t));
}

static inline void
print_cache_header_16(char *buf)
{
   ngx_16_t * cache_header = (ngx_16_t *) buf;

   printf("Nginx 1.6 Cache object:\n");
   printf("%*s: %-22lu %s", width, "ValidSec", cache_header->valid_sec, ctime(&cache_header->valid_sec));
   printf("%*s: %-22lu %s", width, "LastMod", cache_header->last_modified, ctime(&cache_header->last_modified));
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
            ptr=key + 1, key=memchr(ptr, '\n', sz_buf)
        )
    {
        if ( strncasecmp(key + 1, "key: ", 5) == 0 )
            break;
    }

    size_t key_offset;

    if (! key ) {
        fprintf(stderr, "Invalid cache file: %s\n", fname);
        return;
    }

    key_offset = key - buf;

    if ( key_offset == sizeof(ngx_18_t) ) {
        return print_cache_header_18(buf);
    } else if ( key_offset == sizeof(ngx_16_t) ) {
        return print_cache_header_16(buf);
    } else {
        fprintf(stderr, "Invalid cache file: %s\n", fname);
    }
}

static inline int
list_file(const char *fname)
{
    int  fd;
    char buf[4096];

    if ( (fd=open(fname, O_RDONLY)) < 0 ) {
        fprintf(stderr, "Could not open: %s. ", fname);
        perror("Reason");
        return 2;
    }

    if ( read(fd, &buf, sizeof(buf)) < 0 ) {
        fprintf(stderr, "Could not read: %s. ", fname);
        perror("Reason");
        return 3;
    }

    print_cache_header(fname, buf, sizeof(buf));
    close(fd);

    return 0;
}

int main(int argc, const char *argv[])
{
    int rc;

    if ( argc < 2 ) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    for (int i=1; i<argc; ++i)
        if ( (rc=list_file(argv[i])) != 0 )
            return rc;

    return 0;
}