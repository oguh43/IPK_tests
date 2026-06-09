/*******************************************************************************
*                                                                              *
*                        Brno University of Technology                         *
*                      Faculty of Information Technology                       *
*                                                                              *
*                        Počítačové komunikace a sítě                          *
*                                                                              *
*            Author: Hugo Bohacsek [xbohach00 AT stud.fit.vutbr.cz]            *
*                                   Brno 2026                                  *
*                                                                              *
*       Implementation of the 2nd project impairment proxy for testing         *
*                                                                              *
*******************************************************************************/

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROXY_BUF_SZ 65535
#define MAX_MSG 512
#define POLL_US 200000

// Terminal colors
static int g_color;

#define CB_N 16
#define CB_SZ 512
static char g_cb[CB_N][CB_SZ];
static int g_cbi;

static char *cb(void) {
    char *b = g_cb[g_cbi]; g_cbi = (g_cbi + 1) % CB_N;
    return b;
}

static char *_a(const char *code, const char *t) {
    char *b = cb();
    if (g_color) {
        snprintf(b, CB_SZ, "\033[%sm%s\033[0m", code, t);
    } else {
        snprintf(b, CB_SZ, "%s", t);
    }
    return b;
}

#define DIM(t) _a("2", (t))
#define BOLD(t) _a("1", (t))
#define RED(t) _a("1;31", (t))
#define GREEN(t) _a("1;32", (t))
#define YELLOW(t) _a("1;33", (t))
#define BLUE(t) _a("1;34", (t))
#define CYAN(t) _a("36", (t))

// sha256
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g) (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a) (ROR(a,2)^ROR(a,13)^ROR(a,22))
#define S1(e) (ROR(e,6)^ROR(e,11)^ROR(e,25))
#define G0(w) (ROR(w,7)^ROR(w,18)^((w)>>3))
#define G1(w) (ROR(w,17)^ROR(w,19)^((w)>>10))

static const uint32_t K64[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t h[8];
    uint8_t b[64];
    uint64_t tot;
    uint32_t bl;
    uint32_t pad;
} S256;

static void s_init(S256 *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->tot = c->bl = 0;
    c->pad = 0;
}

static void s_blk(S256 *c, const uint8_t *p) {
    uint32_t w[64], s[8];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = G1(w[i-2]) + w[i-7] + G0(w[i-15]) + w[i-16];
    }
    for (int i = 0; i < 8; i++) {
        s[i] = c->h[i];
    }
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = s[7] + S1(s[4]) + CH(s[4],s[5],s[6]) + K64[i] + w[i];
        uint32_t t2 = S0(s[0]) + MAJ(s[0],s[1],s[2]);
        s[7]=s[6]; s[6]=s[5]; s[5]=s[4]; s[4]=s[3]+t1;
        s[3]=s[2]; s[2]=s[1]; s[1]=s[0]; s[0]=t1+t2;
    }
    for (int i = 0; i < 8; i++) {
        c->h[i] += s[i];
    }
}

static void s_feed(S256 *c, const uint8_t *data, size_t n) {
    c->tot += n;
    while (n > 0) {
        size_t r = 64 - c->bl, take = n < r ? n : r;
        memcpy(c->b + c->bl, data, take);
        c->bl += (uint32_t)take; data += take; n -= take;
        if (c->bl == 64) {
            s_blk(c, c->b); c->bl = 0;
        }
    }
}

static void s_done(S256 *c, uint8_t *dig) {
    uint64_t bits = c->tot * 8;
    uint8_t z = 0x80; s_feed(c, &z, 1); z = 0;
    while (c->bl != 56) s_feed(c, &z, 1);
    for (int i = 7; i >= 0; i--) {
        uint8_t byt = (uint8_t)(bits >> (i*8)); s_feed(c, &byt, 1);
    }
    for (int i = 0; i < 8; i++) {
        dig[i*4] = (uint8_t)(c->h[i] >> 24); dig[i*4+1] = (uint8_t)(c->h[i] >> 16);
        dig[i*4+2] = (uint8_t)(c->h[i] >>  8); dig[i*4+3] = (uint8_t) c->h[i];
    }
}

static void sha256hex(const uint8_t *data, size_t len, char *out) {
    S256 c; s_init(&c); s_feed(&c, data, len);
    uint8_t d[32]; s_done(&c, d);
    for (int i = 0; i < 32; i++) {
        sprintf(out + i*2, "%02x", d[i]);
    }
    out[64] = '\0';
}

// time
static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

 // impairment, TestDef and test table
typedef struct {
    float loss_pct, dup_pct, reorder_pct;
    int reorder_delay_ms, jitter_ms;
    float corrupt_pct;
    int delay_ms;
    float trunc_pct;
    int hostile_n;
    int oversized_n;
} Impairment;

typedef struct {
    const char *name;
    const char *desc;
    long input_size;
    Impairment imp;
    int timeout_w;
    int session_timeout;
    int repeat;
    // cppcheck-suppress unusedStructMember
    int _pad;
} TestDef;

// fancy utf chars
#define UTF_ARROW "\xe2\x86\x92"
#define UTF_PM "\xc2\xb1"
#define UTF_DASH "\xe2\x80\x94"

static void appendf(char *dst, size_t cap, size_t *used, const char *fmt, ...) {
    if (!dst || !used || cap == 0 || *used >= cap - 1) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int wr = vsnprintf(dst + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (wr <= 0) {
        return;
    }
    size_t wrote = (size_t)wr;
    size_t rem = cap - *used;
    if (wrote >= rem) {
        *used = cap - 1;
    } else {
        *used += wrote;
    }
}

static const char *imp_desc(const Impairment *m, char *buf, size_t sz) {
    char t[256];
    size_t n = 0;
    t[0] = '\0';
    if (m->loss_pct > 0) appendf(t, sizeof t, &n, "%sloss=%.0f%%", n ? ", " : "", (double)m->loss_pct);
    if (m->dup_pct > 0) appendf(t, sizeof t, &n, "%sdup=%.0f%%", n ? ", " : "", (double)m->dup_pct);
    if (m->reorder_pct > 0) appendf(t, sizeof t, &n, "%sreorder=%.0f%%/%dms", n ? ", " : "", (double)m->reorder_pct, m->reorder_delay_ms);
    if (m->jitter_ms > 0) appendf(t, sizeof t, &n, "%sjitter=" UTF_PM "%dms", n ? ", " : "", m->jitter_ms);
    if (m->corrupt_pct > 0) appendf(t, sizeof t, &n, "%scorrupt=%.0f%%", n ? ", " : "", (double)m->corrupt_pct);
    if (m->trunc_pct > 0) appendf(t, sizeof t, &n, "%struncate=%.0f%%", n ? ", " : "", (double)m->trunc_pct);
    if (m->delay_ms > 0) appendf(t, sizeof t, &n, "%sdelay=%dms", n ? ", " : "", m->delay_ms);
    if (m->hostile_n > 0) appendf(t, sizeof t, &n, "%shostile=%d", n ? ", " : "", m->hostile_n);
    if (m->oversized_n > 0) appendf(t, sizeof t, &n, "%soversized=%d", n ? ", " : "", m->oversized_n);
    snprintf(buf, sz, "%s", n ? t : "clean");
    return buf;
}

// initialiser - loss, dup, reorder, reorder_ms, jitter, corrupt, delay, trunc, hostile, oversized
#define IMPX(l,d,r,rm,j,c,dl,tr,ho,ov) {(float)(l),(float)(d),(float)(r),(rm),(j),(float)(c),(dl),(float)(tr),(ho),(ov)}
#define IMP(l,d,r,rm,j,c,dl) IMPX(l,d,r,rm,j,c,dl,0,0,0)
#define CLEAN IMP(0,0,0,50,0,0,0)
#define TDEF(name,desc,imp,size,tw,to,rep) {(name),(desc),(size),imp,(tw),(to),(rep),0}

static const TestDef TESTS[] = {
    TDEF("normal", "Clean channel, small file", CLEAN, 50000, 10,  60, 1),
    TDEF("normal_large", "Clean channel, 200 KB", CLEAN, 200000, 10,  60, 1),
    TDEF("empty", "Empty file (0 bytes)", CLEAN, 0, 10,  60, 1),
    TDEF("tiny", "Single byte", CLEAN, 1, 10,  60, 1),
    TDEF("binary", "Binary data (all byte values)", CLEAN, 0, 10,  30, 1),
    TDEF("loss_5", "5% packet loss", IMP(5,0,0,50,0,0,0), 80000, 10,  60, 1),
    TDEF("loss_15", "15% packet loss", IMP(15,0,0,50,0,0,0), 80000, 10,  60, 1),
    TDEF("loss_30", "30% packet loss (stress)", IMP(30,0,0,50,0,0,0), 50000, 15,  90, 1),
    TDEF("reorder", "20% reorder, 80 ms delay", IMP(0,0,20,80,0,0,0), 80000, 10,  60, 1),
    TDEF("dup", "15% duplication", IMP(0,15,0,50,0,0,0), 80000, 10,  60, 1),
    TDEF("corrupt", "10% corruption", IMP(0,0,0,50,0,10,0), 80000, 10,  60, 1),
    TDEF("jitter", UTF_PM "50 ms jitter, 20 ms base delay", IMP(0,0,0,50,50,0,20), 80000, 10,  60, 1),
    TDEF("delay", "Fixed 100 ms delay each way", IMP(0,0,0,50,0,0,100), 50000, 10,  60, 1),
    TDEF("combined", "loss=10% dup=8% reorder=10% corrupt=5% jitter=" UTF_PM "30ms", IMP(10,8,10,50,30,5,10), 60000, 15,  90, 1),
    TDEF("timeout_test", "40% loss + 200 ms delay (timeout stress)", IMP(40,0,0,50,0,0,200), 30000, 15,  90, 1),
    TDEF("large_1mb", "1 MB, 5% loss", IMP(5,0,0,50,0,0,0), 1000000, 15, 120, 1),
    TDEF("large_5mb", "5 MB, 3% loss", IMP(3,0,0,50,0,0,0), 5000000, 20, 180, 1),
    TDEF("stdin_stdout", "stdin" UTF_ARROW "stdout pipe transfer", CLEAN, 30000, 10,  60, 1),
    TDEF("ipv6", "IPv6 loopback transfer", CLEAN, 30000, 10,  60, 1),
    TDEF("signal", "SIGTERM during idle " UTF_DASH " clean exit", CLEAN, 0, 10,  10, 1),
    TDEF("bad_args", "Invalid CLI arguments " UTF_ARROW " non-zero exit", CLEAN, 0, 10,  60, 1),
    TDEF("corrupt_only", "A-CORRUPT: 3% corruption, 96 KiB", IMP(0,0,0,50,0,3,0), 98304, 12,  90, 1),
    TDEF("truncate_only", "A-CORRUPT: 2% truncation, 96 KiB", IMPX(0,0,0,50,0,0,0,2,0,0), 98304, 12,  90, 1),
    TDEF("corrupt_trunc", "A-CORRUPT: 3% corrupt + 2% truncate, 96 KiB", IMPX(0,0,0,50,0,3,0,2,0,0), 98304, 12,  90, 1),
    TDEF("pipeline", "A-PIPELINE: RTT 100 ms, must pipeline within 5 s", IMP(0,0,0,50,0,0,50), 262144, 8,  5, 1),
    TDEF("hostile", "A-HOSTILE: garbage datagrams injected, must ignore", IMPX(0,0,0,50,0,0,0,0,40,0), 80000, 12,  90, 1),
    TDEF("oversized", "A-OVERSIZED-IGNORE: ~60 KB datagrams, must ignore", IMPX(0,0,0,50,0,0,0,0,0,4), 80000, 12,  90, 1),
    TDEF("lifecycle", "A-LIFECYCLE: -w idle self-exit timing", CLEAN, 0, 10,  20, 1),
    TDEF("bulk_32m", "A-BULK: 32 MiB clean transfer", CLEAN, 33554432, 30,  120, 1),
    TDEF("help", "--help " UTF_ARROW " exit 0 with non-empty stdout", CLEAN, 0, 10,  10, 1),
    TDEF(NULL, NULL, CLEAN, 0, 0, 0, 0)
};
#define N_TESTS ((int)(sizeof(TESTS)/sizeof(TESTS[0]) - 1))

static const TestDef *find_test(const char *name) {
    for (int i = 0; i < N_TESTS; i++) {
        if (strcmp(TESTS[i].name, name) == 0) {
            return &TESTS[i];
        }
    }
    return NULL;
}

static int is_slow(const char *name) {
    static const char *slow[] = {"large_1mb","large_5mb","timeout_test","loss_30","bulk_32m","corrupt_only","truncate_only","corrupt_trunc",NULL};
    for (int i = 0; slow[i]; i++) {
        if (strcmp(name, slow[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

//  udp impairment Proxy
typedef struct {
    uint8_t *data;
    size_t len;
    int sock_fd;
    struct sockaddr_in dest;
    int delay_us;
} DSSendArg;

static void *delay_send_fn(void *vp) {
    DSSendArg *a = vp;
    if (a->delay_us > 0) {
        usleep((useconds_t)a->delay_us);
    }
    sendto(a->sock_fd, a->data, a->len, 0, (struct sockaddr *)&a->dest, sizeof a->dest);
    free(a->data); free(a);
    return NULL;
}

static void fire_delayed(int sock_fd, const uint8_t *data, size_t len, const struct sockaddr_in *dest, int delay_us) {
    DSSendArg *a = malloc(sizeof *a);
    if (!a) {
        sendto(sock_fd, data, len, 0, (const struct sockaddr *)dest, sizeof *dest);
        return;
    }
    a->data = malloc(len + 1);
    if (!a->data) {
        free(a);
        sendto(sock_fd, data, len, 0, (const struct sockaddr *)dest, sizeof *dest);
        return;
    }
    memcpy(a->data, data, len);
    a->len = len; a->sock_fd = sock_fd; a->dest = *dest; a->delay_us = delay_us;
    pthread_t tid; pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, delay_send_fn, a);
    pthread_attr_destroy(&attr);
}

typedef struct {
    Impairment imp;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int proxy_port, server_port;
    volatile int halt;
    int sock_fd;
    int has_client;
    int inj_hostile, inj_oversized;
    // cppcheck-suppress unusedStructMember
    int _ipad;
    pthread_t tid;
    // IOS HW; why isn't a mutex used here?
    long s_fwd, s_rev, s_fwd_b, s_rev_b;
    long s_drop, s_dup, s_reorder, s_corrupt, s_trunc, s_inject;
} UDPProxy;

// inject a datagram of random bytes toward dest (garbage you must ignore)
static void inject_garbage(int sock_fd, const struct sockaddr_in *dest, size_t size) {
    if (size == 0) {
        size = 1;
    }
    uint8_t *g = malloc(size);
    if (!g) {
        return;
    }
    for (size_t i = 0; i < size; i++) {
        g[i] = (uint8_t)(rand() & 0xff);
    }
    sendto(sock_fd, g, size, 0, (const struct sockaddr *)dest, sizeof *dest);
    free(g);
}

static void proxy_relay(UDPProxy *px, const uint8_t *data, size_t len, const struct sockaddr_in *dest, int is_fwd) {
    /*
        | ||

        || |_
    */
    if (px->imp.loss_pct > 0.0f &&
        (double)rand() / RAND_MAX * 100.0 < (double)px->imp.loss_pct) {
        px->s_drop++; return;
    }

    // corruption
    uint8_t *pkt = malloc(len + 1);
    if (len) {
        memcpy(pkt, data, len);
    }

    if (px->imp.corrupt_pct > 0.0f && len > 0 && (double)rand() / RAND_MAX * 100.0 < (double)px->imp.corrupt_pct) {
        pkt[rand() % (int)len] ^= (uint8_t)((rand() % 255) + 1);
        px->s_corrupt++;
    }

    // truncation
    size_t send_len = len;
    if (px->imp.trunc_pct > 0.0f && len > 4 &&
        (double)rand() / RAND_MAX * 100.0 < (double)px->imp.trunc_pct) {
        size_t maxchop = len / 2;
        size_t chop = 1u + (size_t)(rand() % (int)maxchop);
        send_len = len - chop;
        px->s_trunc++;
    }

    // delay, jitter, reorder
    double delay = px->imp.delay_ms / 1000.0;
    if (px->imp.jitter_ms > 0) {
        delay += ((double)rand() / RAND_MAX * 2.0 - 1.0) * px->imp.jitter_ms / 1000.0;
        if (delay < 0.0) {
            delay = 0.0;
        }
    }

    if (px->imp.reorder_pct > 0.0f && (double)rand() / RAND_MAX * 100.0 < (double)px->imp.reorder_pct) {
        delay += px->imp.reorder_delay_ms / 1000.0;
        px->s_reorder++;
    }

    int delay_us = (int)(delay * 1e6);
    if (delay_us > 1000) {
        fire_delayed(px->sock_fd, pkt, send_len, dest, delay_us);
    } else {
        sendto(px->sock_fd, pkt, send_len, 0, (const struct sockaddr *)dest, sizeof *dest);
    }

    // duplication
    if (px->imp.dup_pct > 0.0f && (double)rand() / RAND_MAX * 100.0 < (double)px->imp.dup_pct) {
        double d2 = delay + 0.003 + (double)rand() / RAND_MAX * 0.022;
        fire_delayed(px->sock_fd, pkt, send_len, dest, (int)(d2 * 1e6));
        px->s_dup++;
    }

    free(pkt);

    if (is_fwd) {
        // garbage injection toward server
        if (px->inj_oversized > 0) {
            inject_garbage(px->sock_fd, dest, 60000);
            px->inj_oversized--;
            px->s_inject++;
        }
        if (px->inj_hostile > 0 && (rand() % 4 == 0)) {
            inject_garbage(px->sock_fd, dest, 20u + (size_t)(rand() % 40));
            px->inj_hostile--;
            px->s_inject++;
        }

        px->s_fwd++;
        px->s_fwd_b += (long)len;
    } else {
        px->s_rev++;
        px->s_rev_b += (long)len;
    }
}

static void *proxy_thread_fn(void *vp) {
    UDPProxy *px = vp;
    uint8_t *buf = malloc(PROXY_BUF_SZ);
    struct sockaddr_in from;
    socklen_t flen;

    while (!px->halt) {
        int fd = px->sock_fd;
        if (fd < 0) {
            break;
        }
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = {0, 300000};
        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            continue;
        }

        flen = sizeof from;
        ssize_t n = recvfrom(fd, buf, PROXY_BUF_SZ, 0, (struct sockaddr *)&from, &flen);
        if (n < 0) {
            if (!px->halt) {
                continue;
            }
            break;
        }

        // routing s->c / c->s
        if (from.sin_addr.s_addr == px->server_addr.sin_addr.s_addr && from.sin_port == px->server_addr.sin_port) {
            if (px->has_client) {
                proxy_relay(px, buf, (size_t)n, &px->client_addr, 0);
            }
        } else {
            if (!px->has_client) {
                px->client_addr = from; px->has_client = 1;
            }
            proxy_relay(px, buf, (size_t)n, &px->server_addr, 1);
        }
    }

    free(buf);
    return NULL;
}

static int proxy_start(UDPProxy *px, int proxy_port, int server_port, const Impairment *imp) {
    memset(px, 0, sizeof *px);
    px->proxy_port = proxy_port;
    px->server_port = server_port;
    px->imp = *imp;
    px->sock_fd = -1;
    px->inj_hostile = imp->hostile_n;
    px->inj_oversized = imp->oversized_n;

    px->server_addr.sin_family = AF_INET;
    px->server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    px->server_addr.sin_port = htons((uint16_t)server_port);

    px->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (px->sock_fd < 0) return -1;
    int one = 1;
    setsockopt(px->sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in ba = {0};
    ba.sin_family = AF_INET;
    ba.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ba.sin_port = htons((uint16_t)proxy_port);
    if (bind(px->sock_fd, (struct sockaddr *)&ba, sizeof ba) < 0) {
        close(px->sock_fd); px->sock_fd = -1; return -1;
    }

    pthread_create(&px->tid, NULL, proxy_thread_fn, px);
    return 0;
}

static void proxy_stop(UDPProxy *px) {
    px->halt = 1;
    int fd = px->sock_fd; px->sock_fd = -1;
    if (fd >= 0) {
        close(fd);
    }
    pthread_join(px->tid, NULL);
}

// port allocation
static int find_free_ports(int n, int start, int *out) {
    int found = 0;
    for (int p = start; p < start + 500 && found < n; p++) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            continue;
        }
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons((uint16_t)p);
        if (bind(s, (struct sockaddr *)&a, sizeof a) == 0) {
            out[found++] = p;
        }
        close(s);
    }
    return (found == n) ? 0 : -1;
}

// process managment
#define STDIO_DEVNULL  0
#define STDIO_PIPE     1
#define STDIO_INHERIT  2

typedef struct {
    pid_t pid;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    int returncode;
    int exited;
} Proc;

static int proc_spawn(Proc *p, const char *const argv[], int in_m, int out_m, int err_m) {
    memset(p, 0, sizeof *p);
    p->stdin_fd = p->stdout_fd = p->stderr_fd = -1;

    int dn = open("/dev/null", O_RDWR);
    int pi[2]={-1,-1}, po[2]={-1,-1}, pe[2]={-1,-1};
    if (in_m  == STDIO_PIPE && pipe(pi) < 0) {
        goto fail;
    }
    if (out_m == STDIO_PIPE && pipe(po) < 0) {
        goto fail;
    }
    if (err_m == STDIO_PIPE && pipe(pe) < 0) {
        goto fail;
    }

    p->pid = fork();
    if (p->pid < 0) {
        goto fail;
    }

    if (p->pid == 0) {
        // child
        int ci = (in_m  == STDIO_DEVNULL) ? dn : (in_m  == STDIO_PIPE) ? pi[0] : STDIN_FILENO;
        int co = (out_m == STDIO_DEVNULL) ? dn : (out_m == STDIO_PIPE) ? po[1] : STDOUT_FILENO;
        int ce = (err_m == STDIO_DEVNULL) ? dn : (err_m == STDIO_PIPE) ? pe[1] : STDERR_FILENO;
        if (ci != STDIN_FILENO) {
            dup2(ci, STDIN_FILENO);
        }
        if (co != STDOUT_FILENO) {
            dup2(co, STDOUT_FILENO);
        }
        if (ce != STDERR_FILENO) {
            dup2(ce, STDERR_FILENO);
        }
        long maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 64) {
            maxfd = 64;
        }
        for (long fd = 3; fd < maxfd; fd++) {
            close((int)fd);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    // parent
    if (dn >= 0) {
        close(dn);
    }
    if (in_m  == STDIO_PIPE) {
        close(pi[0]); p->stdin_fd  = pi[1];
    }
    if (out_m == STDIO_PIPE) {
        close(po[1]); p->stdout_fd = po[0];
    }
    if (err_m == STDIO_PIPE) {
        close(pe[1]); p->stderr_fd = pe[0];
    }
    return 0;

fail:
    if (dn >= 0) {
        close(dn);
    }
    if (pi[0]>=0){
        close(pi[0]);close(pi[1]);
    }
    if (po[0]>=0){
        close(po[0]);close(po[1]);
    }
    if (pe[0]>=0){
        close(pe[0]);close(pe[1]);
    }
    return -1;
}

static int proc_poll(Proc *p) {
    if (p->exited) {
        return 1;
    }
    int st; pid_t r = waitpid(p->pid, &st, WNOHANG);
    if (r == p->pid) {
        p->exited = 1;
        p->returncode = WIFEXITED(st) ? WEXITSTATUS(st) : -(int)WTERMSIG(st);
        return 1;
    }
    return 0;
}

static void proc_reap(Proc *p) {
    int st; waitpid(p->pid, &st, 0);
    p->exited = 1;
    p->returncode = WIFEXITED(st) ? WEXITSTATUS(st) : -(int)WTERMSIG(st);
}

// 1 = on time, 0 = timeout
static int proc_wait_until(Proc *p, double deadline) {
    while (now() < deadline) {
        if (proc_poll(p)) {
            return 1;
        }
        usleep(POLL_US);
    }
    return proc_poll(p);
}

static void proc_terminate(Proc *p) {
    if (p->exited) {
        return;
    }
    kill(p->pid, SIGTERM);
    for (int i = 0; i < 30 && !p->exited; i++) {
        usleep(100000);
        proc_poll(p);
    }
    if (!p->exited) {
        kill(p->pid, SIGKILL); proc_reap(p);
    }
}

// stderr drain (pipe-buffer dEaDlOcK)
typedef struct {
    const char *label;
    int fd;
    int verbose;
} SErr;

static void *serr_fn(void *vp) {
    SErr *s = vp;
    char line[512];
    FILE *f = fdopen(s->fd, "r");
    if (!f) {
        free(s); return NULL;
    }
    while (fgets(line, sizeof line, f)) {
        if (s->verbose) {
            size_t n = strlen(line);
            while (n && (line[n-1]=='\n'||line[n-1]=='\r')) {
                line[--n]='\0';
            }
            if (n) {
                printf("    [%s] %s\n", s->label, line);
            }
        }
    }
    fclose(f);
    return NULL;
}

static void drain_stderr(int stderr_fd, const char *label, int verbose) {
    if (stderr_fd < 0) {
        return;
    }
    SErr *s = malloc(sizeof *s);
    if (!s) {
        close(stderr_fd);
        return;
    }
    s->fd = stderr_fd; s->label = label; s->verbose = verbose;
    pthread_t tid; pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, serr_fn, s);
    pthread_attr_destroy(&attr);
}


// input generation + fmt_bytes
static uint8_t *gen_input(const TestDef *td, size_t *len) {
    if (strcmp(td->name, "tiny") == 0) {
        *len = 1;
        uint8_t *b = malloc(1);
        if (!b) {
            return NULL;
        }
        b[0] = 0x42;
        return b;
    }
    if (strcmp(td->name, "binary") == 0) {
        *len = 256 * 200;
        uint8_t *b = malloc(*len);
        if (!b) {
            return NULL;
        }
        for (int i = 0; i < 200; i++){
            for (int j = 0; j < 256; j++) {
                b[i*256+j] = (uint8_t)j;
            }
        }
        return b;
    }
    if (td->input_size == 0) {
        *len = 0;
        return malloc(1);
    }
    *len = (size_t)td->input_size;
    uint8_t *b = malloc(*len);
    if (!b) {
        return NULL;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        for (size_t i = 0; i < *len; i++) {
            b[i] = (uint8_t)(rand() & 0xff);
        }
        return b;
    }
    size_t done = 0;
    while (done < *len) {
        ssize_t r = read(fd, b + done, *len - done);
        if (r > 0) {
            done += (size_t)r;
        } else {
            break;
        }
    }
    close(fd);
    if (done < *len) {
        for (size_t i = done; i < *len; i++) {
            b[i] = (uint8_t)(rand() & 0xff);
        }
    }
    return b;
}

static const char *fmt_bytes(long n, char *buf, size_t sz) {
    if (n == 0) {
        snprintf(buf, sz, "0 B");
        return buf;
    }
    double v = (double)n;
    int i = 0;
    while (v >= 1024.0 && i < 4) {
        v /= 1024.0; i++;
    }
    if (i == 0) {
        snprintf(buf, sz, "%ld B", n);
    }
    else {
        static const char *u[] = {"B","KB","MB","GB","TB"};
        snprintf(buf, sz, "%.1f %s", v, u[i]);
    }
    return buf;
}

// results
typedef struct {
    long input_size, output_size, first_diff;
    long p_fwd, p_rev, p_drop, p_dup, p_reorder, p_corrupt;
    long p_trunc, p_inject;
    int client_exit, server_exit;
    int has_diff, skipped;
    int exit_code;
    int pad;
    char input_sha[65], output_sha[65];
    char sha_pad[6];
} Det;

typedef struct {
    Det d;
    char msg[MAX_MSG];
    int ok;
    int pad;
} Res;

static Res res_ok(const char *msg, const Det *d) {
    Res r = {0};
    r.ok = 1;
    snprintf(r.msg, MAX_MSG, "%s", msg);
    if (d) {
        r.d = *d;
    } else {
        memset(&r.d, 0, sizeof r.d);
    }
    r.pad = 0;
    r.d.pad = 0;
    memset(r.d.sha_pad, 0, sizeof r.d.sha_pad);
    return r;
}
static Res res_fail(const char *msg, const Det *d) {
    Res r = {0};
    r.ok = 0;
    snprintf(r.msg, MAX_MSG, "%s", msg);
    if (d) {
        r.d = *d;
    } else {
        memset(&r.d, 0, sizeof r.d);
    }
    r.pad = 0;
    r.d.pad = 0;
    memset(r.d.sha_pad, 0, sizeof r.d.sha_pad);
    return r;
}

static Res res_failf(const Det *d, const char *fmt, ...) {
    Res r = {0};
    r.ok = 0;
    if (d) {
        r.d = *d;
    } else {
        memset(&r.d, 0, sizeof r.d);
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r.msg, MAX_MSG, fmt, ap);
    va_end(ap);
    r.pad = 0;
    r.d.pad = 0;
    memset(r.d.sha_pad, 0, sizeof r.d.sha_pad);
    return r;
}

static Res res_okf(const Det *d, const char *fmt, ...) {
    Res r = {0};
    r.ok = 1;
    if (d) {
        r.d = *d;
    } else {
        memset(&r.d, 0, sizeof r.d);
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r.msg, MAX_MSG, fmt, ap);
    va_end(ap);
    r.pad = 0;
    r.d.pad = 0;
    memset(r.d.sha_pad, 0, sizeof r.d.sha_pad);
    return r;
}

static Res res_skip(const char *msg) {
    Res r = {0};
    r.ok = 1;
    r.d.skipped = 1;
    snprintf(r.msg, MAX_MSG, "%s", msg);
    r.pad = 0;
    r.d.pad = 0;
    memset(r.d.sha_pad, 0, sizeof r.d.sha_pad);
    return r;
}


// file - file test
static Res run_standard(const char *binary, const TestDef *td, const char *tmpdir, int verbose, int port_base) {
    static Det d;
    memset(&d, 0, sizeof d);
    (void)td->_pad;
    int ports[2];
    if (find_free_ports(2, port_base, ports) < 0) {
        return res_fail("No free ports", &d);
    }
    int proxy_port = ports[0], server_port = ports[1];
    d.input_size = 0;

    // input generation
    size_t in_len; uint8_t *in_data = gen_input(td, &in_len);
    if (!in_data) {
        return res_fail("Input allocation failed", &d);
    }
    char in_file[128], out_file[128];
    snprintf(in_file,  sizeof in_file,  "%s/input.bin",  tmpdir);
    snprintf(out_file, sizeof out_file, "%s/output.bin", tmpdir);

    FILE *f = fopen(in_file, "wb");
    if (!f) {
        free(in_data);
        return res_fail("Failed to open input file", &d);
    }
    if (in_len) {
        fwrite(in_data, 1, in_len, f);
    }
    fclose(f);

    sha256hex(in_data, in_len, d.input_sha);
    d.input_size = (long)in_len;

    // start proxy
    UDPProxy *px = malloc(sizeof *px);
    if (!px) {
        free(in_data);
        return res_fail("OOM allocating proxy", &d);
    }
    if (proxy_start(px, proxy_port, server_port, &td->imp) < 0) {
        free(px);
        free(in_data);
        return res_fail("Proxy bind failed", &d);
    }
    (void)px->_ipad;

    // start server
    char pw[16], sp[16]; snprintf(pw,sizeof pw,"%d",td->timeout_w);
    snprintf(sp, sizeof sp, "%d", server_port);
    const char *srv_argv[] = {
        binary, "-s", "-p", sp, "-a", "127.0.0.1",
        "-o", out_file, "-w", pw, NULL
    };
    Proc srv;
    if (proc_spawn(&srv, srv_argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_PIPE) < 0) {
        proxy_stop(px);
        free(px);
        free(in_data);
        return res_fail("Failed to start server", &d);
    }
    drain_stderr(srv.stderr_fd, "srv", verbose);
    usleep(150000);  // server is binding

    // start client
    char pp[16]; snprintf(pp, sizeof pp, "%d", proxy_port);
    const char *cli_argv[] = {
        binary, "-c", "-a", "127.0.0.1", "-p", pp,
        "-i", in_file, "-w", pw, NULL
    };
    Proc cli;
    if (proc_spawn(&cli, cli_argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_PIPE) < 0) {
        proc_terminate(&srv);
        proxy_stop(px);
        free(px);
        free(in_data);
        return res_fail("Failed to start client", &d);
    }
    drain_stderr(cli.stderr_fd, "cli", verbose);

    // wait for both with deadline
    double deadline = now() + td->session_timeout;
    int cli_done = 0, srv_done = 0;
    while (now() < deadline) {
        if (!cli_done && proc_poll(&cli)) {
            cli_done = 1;
        }
        if (!srv_done && proc_poll(&srv)) {
            srv_done = 1;
        }
        if (cli_done && srv_done) {
            break;
        }
        usleep(POLL_US);
    }

    if (!cli_done) {
        proc_terminate(&cli);
    }
    if (!srv_done) {
        proc_terminate(&srv);
    }
    proxy_stop(px);

    d.client_exit = cli.returncode;
    d.server_exit = srv.returncode;
    d.p_fwd = px->s_fwd; d.p_rev = px->s_rev;
    d.p_drop = px->s_drop; d.p_dup = px->s_dup;
    d.p_reorder = px->s_reorder; d.p_corrupt = px->s_corrupt;
    d.p_trunc = px->s_trunc; d.p_inject = px->s_inject;
    free(px);

    if (!cli_done || !srv_done) {
        char who[64] = "";
        if (!cli_done) {
            strcat(who, "client");
        }
        if (!srv_done) {
            if (who[0]) {
                strcat(who,"+");
            }
            strcat(who,"server");
        }
        free(in_data);
        return res_failf(&d, "Timeout: %s didn't finish in %ds", who, td->session_timeout);
    }
    if (cli.returncode != 0) {
        free(in_data);
        return res_failf(&d, "Client exited with code %d", cli.returncode);
    }
    if (srv.returncode != 0) {
        free(in_data);
        return res_failf(&d, "Server exited with code %d", srv.returncode);
    }

    // verify output
    struct stat st;
    if (stat(out_file, &st) < 0) {
        free(in_data); return res_fail("Output file not created", &d);
    }
    size_t out_len = (size_t)st.st_size;
    uint8_t *out_data = malloc(out_len + 1);
    if (!out_data) {
        free(in_data);
        return res_fail("Output buffer allocation failed", &d);
    }
    FILE *of = fopen(out_file, "rb");
    if (!of) {
        free(in_data);
        free(out_data);
        return res_fail("Failed to open output file", &d);
    }
    if (out_len) {
        fread(out_data, 1, out_len, of);
    }
    fclose(of);

    sha256hex(out_data, out_len, d.output_sha);
    d.output_size = (long)out_len;

    if (out_len != in_len) {
        free(in_data);
        free(out_data);
        return res_failf(&d, "Size mismatch: sent %zu, received %zu", in_len, out_len);
    }
    if (strcmp(d.input_sha, d.output_sha) != 0) {
        for (size_t i = 0; i < in_len; i++) {
            if (in_data[i] != out_data[i]) {
                d.first_diff = (long)i; d.has_diff = 1; break;
            }
        }
        free(in_data);
        free(out_data);
        if (d.has_diff) {
            return res_failf(&d, "Checksum mismatch (first diff at byte %ld)", d.first_diff);
        }
        return res_fail("Checksum mismatch", &d);
    }

    free(in_data); free(out_data);
    return res_ok("Checksums match", &d);
}

// stdin - stdout test
static Res run_stdin_stdout(const char *binary, const TestDef *td, int verbose, int port_base) {
    Det d = {0};
    (void)td->_pad;
    int ports[2];
    if (find_free_ports(2, port_base, ports) < 0) {
        return res_fail("No free ports", &d);
    }
    int proxy_port = ports[0], server_port = ports[1];

    size_t in_len; uint8_t *in_data = gen_input(td, &in_len);
    if (!in_data) {
        return res_fail("Input allocation failed", &d);
    }
    sha256hex(in_data, in_len, d.input_sha);
    d.input_size = (long)in_len;

    UDPProxy px;
    proxy_start(&px, proxy_port, server_port, &td->imp);
    (void)px._ipad;

    char pw[16], sp[16]; snprintf(pw,sizeof pw,"%d",td->timeout_w);
    snprintf(sp, sizeof sp, "%d", server_port);
    const char *srv_argv[] = {
        binary, "-s", "-p", sp, "-a", "127.0.0.1", "-w", pw, NULL
    };
    Proc srv;
    proc_spawn(&srv, srv_argv, STDIO_DEVNULL, STDIO_PIPE, STDIO_PIPE);
    drain_stderr(srv.stderr_fd, "srv", verbose);
    usleep(150000);

    char pp[16]; snprintf(pp, sizeof pp, "%d", proxy_port);
    const char *cli_argv[] = {
        binary, "-c", "-a", "127.0.0.1", "-p", pp, "-w", pw, NULL
    };
    Proc cli;
    proc_spawn(&cli, cli_argv, STDIO_PIPE, STDIO_DEVNULL, STDIO_PIPE);
    drain_stderr(cli.stderr_fd, "cli", verbose);

    // feed stdin to client
    if (in_len) {
        write(cli.stdin_fd, in_data, in_len);
    }
    close(cli.stdin_fd); cli.stdin_fd = -1;

    double deadline = now() + td->session_timeout;
    proc_wait_until(&cli, deadline);
    proc_wait_until(&srv, deadline);
    if (!cli.exited) {
        proc_terminate(&cli);
    }
    if (!srv.exited) {
        proc_terminate(&srv);
    }
    proxy_stop(&px);

    d.client_exit = cli.returncode;
    d.server_exit = srv.returncode;

    if (cli.returncode != 0) {
        free(in_data);
        return res_failf(&d, "Client exit %d", cli.returncode);
    }
    if (srv.returncode != 0) {
        free(in_data);
        return res_failf(&d, "Server exit %d", srv.returncode);
    }

    // read server's stdout
    uint8_t *chunk = malloc(4096);
    size_t out_len = 0;
    uint8_t *out_data = NULL;
    ssize_t nr;
    if (!chunk) {
        free(in_data);
        return res_fail("OOM while reading stdout", &d);
    }
    while ((nr = read(srv.stdout_fd, chunk, 4096)) > 0) {
        uint8_t *tmp = realloc(out_data, out_len + (size_t)nr);
        if (!tmp) {
            free(chunk);
            close(srv.stdout_fd);
            free(in_data);
            free(out_data);
            return res_fail("Output realloc failed", &d);
        }
        out_data = tmp;
        memcpy(out_data + out_len, chunk, (size_t)nr);
        out_len += (size_t)nr;
    }
    free(chunk);
    close(srv.stdout_fd);

    sha256hex(out_data ? out_data : (uint8_t*)"", out_len, d.output_sha);
    d.output_size = (long)out_len;

    if (out_len != in_len || strcmp(d.input_sha, d.output_sha) != 0) {
        free(in_data);
        free(out_data);
        return res_failf(&d, "Mismatch: sent %zu B, got %zu B", in_len, out_len);
    }

    free(in_data); free(out_data);
    return res_ok("stdin" UTF_ARROW "stdout verified", &d);
}

// ipv6 ::1 test
static Res run_ipv6(const char *binary, const TestDef *td, const char *tmpdir, int verbose, int port_base) {
    static Det d;
    memset(&d, 0, sizeof d);

    int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s6 < 0) {
        return res_skip("IPv6 not available "UTF_DASH" skipped");
    }
    struct sockaddr_in6 probe = {0};
    probe.sin6_family = AF_INET6;
    probe.sin6_addr = in6addr_loopback;
    probe.sin6_port = 0;
    if (bind(s6, (struct sockaddr *)&probe, sizeof probe) < 0) {
        close(s6);
        return res_skip("IPv6 loopback unavailable "UTF_DASH" skipped");
    }
    close(s6);

    int ports[1];
    if (find_free_ports(1, port_base, ports) < 0) {
        return res_fail("No free ports",&d);
    }
    int port = ports[0];

    size_t in_len; uint8_t *in_data = gen_input(td, &in_len);
    if (!in_data) {
        return res_fail("Input allocation failed", &d);
    }
    char in_file[128], out_file[128];
    snprintf(in_file,  sizeof in_file,  "%s/input6.bin",  tmpdir);
    snprintf(out_file, sizeof out_file, "%s/output6.bin", tmpdir);
    FILE *f = fopen(in_file, "wb");
    if (!f) {
        free(in_data);
        return res_fail("Failed to open IPv6 input file", &d);
    }
    if (in_len) {
        fwrite(in_data, 1, in_len, f);
    }
    fclose(f);
    sha256hex(in_data, in_len, d.input_sha);
    d.input_size = (long)in_len;

    char pw[16], sp[16]; snprintf(pw,sizeof pw,"%d",td->timeout_w);
    snprintf(sp, sizeof sp, "%d", port);
    const char *srv_argv[] = {binary,"-s","-p",sp,"-a","::1","-o",out_file,"-w",pw,NULL};
    const char *cli_argv[] = {binary,"-c","-a","::1","-p",sp,"-i",in_file,"-w",pw,NULL};
    Proc srv, cli;
    proc_spawn(&srv, srv_argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_PIPE);
    drain_stderr(srv.stderr_fd, "srv", verbose);
    usleep(150000);
    proc_spawn(&cli, cli_argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_PIPE);
    drain_stderr(cli.stderr_fd, "cli", verbose);

    double deadline = now() + td->session_timeout;
    proc_wait_until(&cli, deadline);
    proc_wait_until(&srv, deadline);
    if (!cli.exited) {
        proc_terminate(&cli);
    }
    if (!srv.exited) {
        proc_terminate(&srv);
    }

    d.client_exit = cli.returncode; d.server_exit = srv.returncode;
    if (cli.returncode != 0) {
        free(in_data);
        return res_failf(&d, "Client exit %d", cli.returncode);
    }
    if (srv.returncode != 0) {
        free(in_data);
        return res_failf(&d, "Server exit %d", srv.returncode);
    }

    struct stat st;
    if (stat(out_file, &st) < 0) {
        free(in_data);
        return res_fail("No output file",&d);
    }
    size_t out_len = (size_t)st.st_size;
    uint8_t *out_data = malloc(out_len + 1);
    if (!out_data) {
        free(in_data);
        return res_fail("IPv6 output allocation failed", &d);
    }
    FILE *of = fopen(out_file, "rb");
    if (!of) {
        free(in_data);
        free(out_data);
        return res_fail("Failed to open IPv6 output file", &d);
    }
    if (out_len) {
        fread(out_data, 1, out_len, of);
    }
    fclose(of);
    sha256hex(out_data, out_len, d.output_sha);
    d.output_size = (long)out_len;

    int ok = (out_len == in_len && strcmp(d.input_sha, d.output_sha) == 0);
    free(in_data); free(out_data);
    return ok ? res_ok("IPv6 transfer verified",&d) : res_fail("Checksum mismatch",&d);
}

// clean-exit test
static Res run_signal_test(const char *binary, int verbose, int port_base) {
    Det d = {0};
    int ports[1];
    if (find_free_ports(1, port_base, ports) < 0) {
        return res_fail("No free ports",&d);
    }
    char sp[16]; snprintf(sp, sizeof sp, "%d", ports[0]);

    // server
    const char *srv_argv[] = {binary,"-s","-p",sp,"-a","127.0.0.1","-w","5",NULL};
    Proc srv; proc_spawn(&srv, srv_argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_PIPE);
    drain_stderr(srv.stderr_fd, "srv", verbose);
    usleep(500000);

    kill(srv.pid, SIGTERM);
    if (!proc_wait_until(&srv, now() + 5.0)) {
        proc_terminate(&srv);
        return res_fail("Server did not exit within 5s of SIGTERM",&d);
    }
    d.exit_code = srv.returncode;
    // crashed = terminated by a signal that is NOT SIGTERM
    if (srv.returncode < 0 && srv.returncode != -SIGTERM) {
        return res_failf(&d, "Server crashed with signal %d", -srv.returncode);
    }

    // client
    const char *cli_argv[] = {binary,"-c","-a","127.0.0.1","-p",sp,"-w","5",NULL};
    Proc cli; proc_spawn(&cli, cli_argv, STDIO_PIPE, STDIO_DEVNULL, STDIO_PIPE);
    drain_stderr(cli.stderr_fd, "cli", verbose);
    usleep(500000);

    kill(cli.pid, SIGTERM);
    if (!proc_wait_until(&cli, now() + 5.0)) {
        proc_terminate(&cli);
        return res_fail("Client did not exit within 5s of SIGTERM",&d);
    }
    d.client_exit = cli.returncode;
    // crashed = terminated by a signal that is NOT SIGTERM
    if (cli.returncode < 0 && cli.returncode != -SIGTERM) {
        return res_failf(&d, "Client crashed with signal %d", -cli.returncode);
    }

    return res_ok("Clean SIGTERM handling",&d);
}

// help conformance; exit 0 with non-empty stdout
static Res run_help(const char *binary, int verbose) {
    Det d = {0};
    const char *argv[] = {binary, "--help", NULL};
    Proc p;
    if (proc_spawn(&p, argv, STDIO_DEVNULL, STDIO_PIPE, STDIO_PIPE) < 0) {
        return res_fail("Failed to spawn process", &d);
    }
    drain_stderr(p.stderr_fd, "help", verbose);

    int flags = fcntl(p.stdout_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(p.stdout_fd, F_SETFL, flags | O_NONBLOCK);
    }

    static char obuf[8192];
    size_t got = 0;
    double deadline = now() + 5.0;
    while (now() < deadline) {
        if (got < sizeof obuf - 1) {
            ssize_t r = read(p.stdout_fd, obuf + got, sizeof obuf - 1 - got);
            if (r > 0) {
                got += (size_t)r;
                continue;
            }
        }
        if (proc_poll(&p)) {
            ssize_t r;
            while (got < sizeof obuf - 1 && (r = read(p.stdout_fd, obuf + got, sizeof obuf - 1 - got)) > 0) {
                got += (size_t)r;
            }
            break;
        }
        usleep(20000);
    }

    int finished = proc_poll(&p);
    if (!finished) {
        proc_terminate(&p);
        if (p.stdout_fd >= 0) {
            close(p.stdout_fd);
        }
        return res_fail("--help did not exit within 5s", &d);
    }
    if (p.stdout_fd >= 0) {
        close(p.stdout_fd);
    }
    d.exit_code = p.returncode;
    d.output_size = (long)got;
    if (p.returncode != 0) {
        return res_failf(&d, "--help exited with code %d (expected 0)", p.returncode);
    }
    if (got == 0) {
        return res_fail("--help produced no stdout output", &d);
    }
    return res_ok("--help exits 0 with usage text", &d);
}

// time how long an idle server runs before self-exiting under -w
static double measure_idle_exit(const char *binary, int port, int w, double cap, int *exited_ok, int verbose) {
    char sp[16], pw[16];
    snprintf(sp, sizeof sp, "%d", port);
    snprintf(pw, sizeof pw, "%d", w);
    const char *srv_argv[] = {binary, "-s", "-p", sp, "-a", "127.0.0.1", "-w", pw, NULL};
    Proc srv;
    if (proc_spawn(&srv, srv_argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_PIPE) < 0) {
        *exited_ok = 0;
        return -1.0;
    }
    drain_stderr(srv.stderr_fd, "srv", verbose);
    double t0 = now();
    double deadline = t0 + cap;
    while (now() < deadline) {
        if (proc_poll(&srv)) {
            *exited_ok = 1;
            return now() - t0;
        }
        usleep(20000);
    }
    proc_terminate(&srv);
    *exited_ok = 0;
    return now() - t0;
}

// -w idle timeout must be honored (w=3 self-exits later than w=1)
static Res run_lifecycle(const char *binary, int verbose, int port_base) {
    Det d = {0};
    int ports[2];
    if (find_free_ports(2, port_base, ports) < 0) {
        return res_fail("No free ports", &d);
    }
    int ok1 = 0, ok3 = 0;
    double t1 = measure_idle_exit(binary, ports[0], 1, 6.0, &ok1, verbose);
    double t3 = measure_idle_exit(binary, ports[1], 3, 10.0, &ok3, verbose);

    if (!ok1) {
        return res_failf(&d, "Server with -w 1 did not self-exit (waited %.1fs)", t1);
    }
    if (!ok3) {
        return res_failf(&d, "Server with -w 3 did not self-exit (waited %.1fs)", t3);
    }
    // real idle timeout makes -w 3 outlast -w 1 by ~2s
    // impls that exit immediately show diff ~0.00s
    if (t3 - t1 < 1.0) {
        return res_failf(&d, "-w not honored: exit times too close (w1=%.2fs, w3=%.2fs)", t1, t3);
    }
    if (t1 > 3.0) {
        return res_failf(&d, "-w 1 idle exit too slow (%.2fs, expected ~1s)", t1);
    }
    return res_okf(&d, "Idle -w timeout honored (w1=%.2fs, w3=%.2fs)", t1, t3);
}

// bad-args test
static Res run_bad_args(const char *binary) {
    Det d = {0};

    struct { const char *args[8]; const char *desc; } cases[] = {
        { {NULL}, "no arguments" },
        { {"-c","-s","-p","9000",NULL}, "both -c and -s" },
        { {"-c","-p","9000",NULL}, "client without -a" },
        { {"-s",NULL}, "server without -p" },
        { {"-c","-a","127.0.0.1",NULL}, "client without -p" },
        { {"-c","-a","127.0.0.1","-p","9000","-w","0",NULL}, "non-positive -w 0" },
        { {"-c","-a","127.0.0.1","-p","9000","-w","-1",NULL}, "negative -w -1" },
    };
    int n = (int)(sizeof cases / sizeof cases[0]);

    for (int i = 0; i < n; i++) {
        // build argv - binary + case args
        const char *argv[16]; int ac = 0;
        argv[ac++] = binary;
        for (int j = 0; cases[i].args[j]; j++) {
            argv[ac++] = cases[i].args[j];
        }
        argv[ac] = NULL;

        Proc p;
        if (proc_spawn(&p, argv, STDIO_DEVNULL, STDIO_DEVNULL, STDIO_DEVNULL) < 0)
            return res_fail("Failed to spawn process",&d);

        if (!proc_wait_until(&p, now() + 5.0)) {
            proc_terminate(&p);
            return res_failf(&d, "Hung on bad args: %s", cases[i].desc);
        }
        if (p.returncode == 0) {
            return res_failf(&d, "Exited 0 on invalid args (%s)", cases[i].desc);
        }
    }
    return res_ok("All invalid args rejected",&d);
}

// dispatch + tmpdir cleanup
static Res run_single(const char *binary, const TestDef *td, int verbose, int port_base) {
    char tmpdir[64];
    snprintf(tmpdir, sizeof tmpdir, "/tmp/ipk-rdt-%s-XXXXXX", td->name);
    if (!mkdtemp(tmpdir)) {
        Res r = {0};
        r.ok = 0;
        snprintf(r.msg, MAX_MSG, "mkdtemp failed");
        return r;
    }

    Res res;
    if (strcmp(td->name,"stdin_stdout")==0) {
        res = run_stdin_stdout(binary,td,verbose,port_base);
    } else if (strcmp(td->name,"ipv6" )==0) {
        res = run_ipv6(binary,td,tmpdir,verbose,port_base);
    } else if (strcmp(td->name,"signal" )==0) {
        res = run_signal_test(binary,verbose,port_base);
    } else if (strcmp(td->name,"bad_args" )==0) {
        res = run_bad_args(binary);
    } else if (strcmp(td->name,"lifecycle" )==0) {
        res = run_lifecycle(binary,verbose,port_base);
    } else if (strcmp(td->name,"help" )==0) {
        res = run_help(binary,verbose);
    } else {
        res = run_standard(binary,td,tmpdir,verbose,port_base);
    }

    // cleanup
    size_t cmd_len = strlen(tmpdir) + 8;
    char *cmd = malloc(cmd_len);
    if (cmd) {
        snprintf(cmd, cmd_len, "rm -rf %s", tmpdir);
        system(cmd);
        free(cmd);
    }

    return res;
}

// help
static int valid_shell_name(const char *s) {
    static const char *v[] = {"c","clisp","csharp","go","java","python","rust","zig",NULL};
    for (int i = 0; v[i]; i++) {
        if (strcmp(s, v[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// submission PATH : validate archive structure, do not run binary tests
static int run_submission(const char *zippath) {
    static char tmpl[] = "/tmp/ipk-rdt-sub-XXXXXX";
    static char cmd[8192];
    static char root[3072];
    static char path[4096];
    static char line[1024];
    int fails = 0, warns = 0;

    printf("\n  %s\n", BOLD("IPK-RDT Submission Structure Check"));
    printf("  %s %s\n\n", DIM("Archive:"), zippath);

    // 1) archive filename
    const char *base = strrchr(zippath, '/');
    base = base ? base + 1 : zippath;
    size_t blen = strlen(base);
    int name_ok = 0;
    if (blen > 4 && strcmp(base + blen - 4, ".zip") == 0) {
        size_t stem = blen - 4;
        if (stem == 6) {
            int alld = 1;
            for (size_t i = 0; i < stem; i++) {
                if (!isdigit((unsigned char)base[i])) { alld = 0; break; }
            }
            if (alld) name_ok = 1; // 123456.zip
        }
        if (stem >= 3 && base[0] == 'x' &&
            isalpha((unsigned char)base[1]) &&
            isdigit((unsigned char)base[stem - 1]) &&
            isdigit((unsigned char)base[stem - 2])) {
            name_ok = 1; // xlogin00.zip
        }
    }
    if (name_ok) {
        printf("  %s  archive name '%s' matches xlogin00.zip / 123456.zip\n", GREEN("PASS"), base);
    } else {
        printf("  %s  archive name '%s' must be xlogin00.zip or 123456.zip (NOT x123456.zip)\n", RED("FAIL"), base);
        fails++;
    }

    // 2) extract
    if (system("command -v unzip >/dev/null 2>&1") != 0) {
        printf("  %s  'unzip' not available; cannot inspect archive contents\n", YELLOW("WARN"));
        printf("\n  %s (%d failure%s, %d warning%s)\n\n", BOLD("Result:"), fails, fails == 1 ? "" : "s", warns + 1, "s");
        return fails > 0 ? 1 : 0;
    }
    if (!mkdtemp(tmpl)) {
        printf("  %s  could not create temp dir for extraction\n", RED("FAIL"));
        return 1;
    }
    snprintf(cmd, sizeof cmd, "unzip -q -o '%s' -d '%s' >/dev/null 2>&1", zippath, tmpl);
    if (system(cmd) != 0) {
        printf("  %s  failed to unzip archive (is it a valid zip?)\n", RED("FAIL"));
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", tmpl);
        if (system(cmd) != 0) { /* best effort */ }
        printf("\n  %s (%d failure%s)\n\n", BOLD("Result:"), fails + 1, "s");
        return 1;
    }

    // 3) nested wrapper directory
    snprintf(root, sizeof root, "%s", tmpl);
    DIR *dp = opendir(tmpl);
    int entries = 0;
    char only[256] = "";
    if (dp) {
        const struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
            entries++;
            if (entries == 1) {
                snprintf(only, sizeof only, "%s", de->d_name);
            }
        }
        closedir(dp);
    }
    if (entries == 1 && only[0]) {
        snprintf(path, sizeof path, "%s/%s", tmpl, only);
        struct stat sst;
        if (stat(path, &sst) == 0 && S_ISDIR(sst.st_mode)) {
            snprintf(path, sizeof path, "%s/Makefile", tmpl);
            struct stat mtop;
            if (stat(path, &mtop) != 0) {
                printf("  %s  archive wraps all files in a nested '%s/' directory\n", RED("FAIL"), only);
                fails++;
                snprintf(root, sizeof root, "%s/%s", tmpl, only);
            }
        }
    }

    // 4) Makefile at root
    snprintf(path, sizeof path, "%s/Makefile", root);
    struct stat mst;
    int have_makefile = (stat(path, &mst) == 0);
    if (have_makefile) {
        printf("  %s  Makefile present at archive root\n", GREEN("PASS"));
    } else {
        printf("  %s  no Makefile at archive root\n", RED("FAIL"));
        fails++;
    }

    // 5) `make environment` target
    if (have_makefile) {
        snprintf(cmd, sizeof cmd, "cd '%s' && timeout 15 make environment 2>/dev/null", root);
        FILE *mp = popen(cmd, "r");
        if (!mp) {
            printf("  %s  could not run 'make environment'\n", RED("FAIL"));
            fails++;
        } else {
            int saw_echo = 0, nlines = 0;
            char lastname[1024];
            lastname[0] = '\0';
            while (fgets(line, sizeof line, mp)) {
                size_t n = strlen(line);
                while (n && (line[n-1]=='\n' || line[n-1]=='\r' || line[n-1]==' ' || line[n-1]=='\t')) {
                    line[--n] = '\0';
                }
                if (n == 0) {
                    continue;
                }
                nlines++;
                if (strncmp(line, "echo", 4u) == 0) {
                    saw_echo = 1;
                }
                snprintf(lastname, sizeof lastname, "%s", line);
            }
            if (pclose(mp) == -1) { /* ignore */ }
            if (saw_echo) {
                printf("  %s  'environment' echoes the command line " UTF_DASH " missing '@' prefix on echo\n", RED("FAIL"));
                fails++;
            } else if (nlines == 0) {
                printf("  %s  'environment' target produced no output\n", RED("FAIL"));
                fails++;
            } else if (!valid_shell_name(lastname)) {
                printf("  %s  'environment' printed '%s' (must be: c clisp csharp go java python rust zig)\n", RED("FAIL"), lastname);
                fails++;
            } else {
                printf("  %s  'environment' prints valid nix shell '%s'\n", GREEN("PASS"), lastname);
            }
        }
    }

    // 6) recommended files
    snprintf(path, sizeof path, "%s/LICENSE", root);
    if (stat(path, &mst) != 0) {
        printf("  %s  LICENSE not found at root\n", YELLOW("WARN")); warns++;
    }
    snprintf(path, sizeof path, "%s/CHANGELOG.md", root);
    if (stat(path, &mst) != 0) {
        printf("  %s  CHANGELOG.md not found at root\n", YELLOW("WARN")); warns++;
    }

    // cleanup + verdict
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", tmpl);
    if (system(cmd) != 0) { /* best effort */ }

    printf("\n  %s ", BOLD("Result:"));
    if (fails == 0) {
        printf("%s", GREEN("structure OK"));
    } else {
        printf("%s", RED("structure problems"));
    }
    printf("  (%d failure%s, %d warning%s)\n\n", fails, fails == 1 ? "" : "s", warns, warns == 1 ? "" : "s");
    return fails > 0 ? 1 : 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "  -b, --binary PATH      Path to ipk-rdt binary  (default: ./ipk-rdt)\n"
        "  -t, --test LIST        Comma-separated test names to run\n"
        "  -l, --list             List available tests and exit\n"
        "  -v, --verbose          Show stderr from ipk-rdt processes\n"
        "      --port-base N      Base UDP port  (default: 20000)\n"
        "  -f, --fast             Skip slow tests (large files, high loss)\n"
        "      --submission ZIP   Validate submission archive structure and exit\n"
        "  -h, --help             Show this help\n"
        "\n"
        "Examples:\n"
        "  %s                         Run all tests\n"
        "  %s -t normal               Run one test\n"
        "  %s -t loss_5,reorder -v    Run two tests, verbose\n"
        "  %s --list                  List tests\n",
        prog, prog, prog, prog, prog);
}

// main
int main(int argc, char *argv[]) {
    g_color = isatty(STDOUT_FILENO);
    srand((unsigned)time(NULL));

    static const struct option lopts[] = {
        {"binary", required_argument, NULL, 'b'},
        {"test", required_argument, NULL, 't'},
        {"list", no_argument, NULL, 'l'},
        {"verbose", no_argument, NULL, 'v'},
        {"port-base", required_argument, NULL, 'P'},
        {"fast", no_argument, NULL, 'f'},
        {"submission", required_argument, NULL, 'S'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    const char *binary = "./ipk-rdt";
    const char *test_arg = NULL;
    const char *submission = NULL;
    int list_mode = 0, verbose = 0, fast = 0, port_base = 20000;
    int opt;
    while ((opt = getopt_long(argc, argv, "b:t:lvfhP:", lopts, NULL)) != -1) {
        switch (opt) {
            case 'b': binary = optarg; break;
            case 't': test_arg = optarg; break;
            case 'l': list_mode = 1; break;
            case 'v': verbose = 1; break;
            case 'P': port_base = atoi(optarg); break;
            case 'f': fast = 1; break;
            case 'S': submission = optarg; break;
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
        }
    }

    // submission structure check runs standalone (no binary needed)
    if (submission) {
        return run_submission(submission);
    }

    // list tests
    if (list_mode) {
        printf("\n  %-16s %8s  %7s  %s\n", "Name", "Size", "Timeout", "Description");
        printf("  %-16s %8s  %7s  %s\n",
               "────────────────","────────","───────","─────────────────────────────────────────────");
        for (int i = 0; i < N_TESTS; i++) {
            const TestDef *td = &TESTS[i];
            char sz[32], to[16];
            if (td->input_size > 0) {
                fmt_bytes(td->input_size, sz, sizeof sz);
            } else {
                snprintf(sz, sizeof sz, "special");
            }
            snprintf(to, sizeof to, "%ds", td->session_timeout);
            printf("  %-16s %8s  %7s  %s\n", td->name, sz, to, td->desc);
        }
        printf("\n");
        return 0;
    }

    // check binary
    struct stat st;
    if (stat(binary, &st) < 0) {
        printf("\n  %s: Binary not found: %s\n", RED("Error"), BOLD(binary));
        printf("  Build your project first, then run this script.\n\n");
        return 1;
    }
    if (access(binary, X_OK) < 0) {
        printf("\n  %s: Binary not executable: %s\n", RED("Error"), BOLD(binary));
        printf("  Try: chmod +x %s\n\n", binary);
        return 1;
    }

    char *abs_binary = malloc(4096);
    if (abs_binary && realpath(binary, abs_binary)) binary = abs_binary;

    // select tests
    const char **selected = calloc((size_t)N_TESTS + 1u, sizeof *selected);
    int n_sel = 0;
    if (!selected) {
        free(abs_binary);
        printf("\n  %s: Out of memory\n\n", RED("Error"));
        return 1;
    }

    const char **failed_names = calloc((size_t)N_TESTS, sizeof *failed_names);
    if (!failed_names) {
        free(selected);
        free(abs_binary);
        printf("\n  %s: Out of memory\n\n", RED("Error"));
        return 1;
    }

    if (test_arg) {
        // parse comma-separated list
        char *buf = strdup(test_arg);
        if (!buf) {
            free(failed_names);
            free(selected);
            free(abs_binary);
            printf("\n  %s: Out of memory\n\n", RED("Error"));
            return 1;
        }
        char *tok = strtok(buf, ",");
        while (tok) {
            while (*tok == ' ') {
                tok++;
            }
            char *end = tok + strlen(tok) - 1;
            while (end > tok && *end == ' ') {
                *end-- = '\0';
            }
            if (!find_test(tok)) {
                free(buf);
                free(failed_names);
                free(selected);
                free(abs_binary);
                printf("\n  %s: Unknown test: %s\n", RED("Error"), BOLD(tok));
                printf("  Run with --list to see available tests.\n\n");
                return 1;
            }
            selected[n_sel++] = tok;
            tok = strtok(NULL, ",");
        }
        test_arg = buf;
    } else {
        for (int i = 0; i < N_TESTS; i++) {
            if (!fast || !is_slow(TESTS[i].name)) {
                selected[n_sel++] = TESTS[i].name;
            }
        }
    }

    // header
    printf("\n  %s\n", BOLD("IPK-RDT Test Harness"));
    printf("  %s %s\n", DIM("Binary:"), binary);
    printf("  %s %d\n", DIM("Tests: "), n_sel);
    printf("  %s\n\n", DIM("\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"));

    int n_pass = 0, n_fail = 0, n_skip = 0;
    int n_failed_names = 0;
    double t0 = now();
    Res *run_res = malloc(sizeof *run_res);
    if (!run_res) {
        if (test_arg) {
            free((void *)test_arg);
        }
        free(failed_names);
        free(selected);
        free(abs_binary);
        printf("\n  %s: Out of memory\n\n", RED("Error"));
        return 1;
    }

    for (int i = 0; i < n_sel; i++) {
        const TestDef *td = find_test(selected[i]);
        char imp_buf[128]; imp_desc(&td->imp, imp_buf, sizeof imp_buf);
        char sz_buf[32];
        const char *sz_str = (td->input_size > 0) ? fmt_bytes(td->input_size, sz_buf, sizeof sz_buf) : "special";

        printf("  [%d/%d] %s  %s\n", i+1, n_sel, BOLD(td->name), DIM(td->desc));
        if (strcmp(imp_buf,"clean") != 0) {
            printf("         %s %s\n", DIM("network:"), CYAN(imp_buf));
        }
        if (td->input_size > 0) {
            printf("         %s %s\n", DIM("input:  "), sz_str);
        }

        int runs = td->repeat > 0 ? td->repeat : 1;
        double test_t0 = now();
        for (int run = 0; run < runs; run++) {
            *run_res = run_single(binary, td, verbose, port_base);
            if (!run_res->ok || run_res->d.skipped) {
                break;
            }
        }
        double elapsed = now() - test_t0;

        char elapsed_buf[32]; snprintf(elapsed_buf, sizeof elapsed_buf, "(%.1fs)", elapsed);

        if (run_res->d.skipped) {
            printf("         %s  %s  %s\n\n", YELLOW("SKIP"), run_res->msg, DIM(elapsed_buf));
            n_skip++;
            continue;
        }

        const char *tag = run_res->ok ? GREEN("PASS") : RED("FAIL");
        printf("         %s  %s  %s\n", tag, run_res->msg, DIM(elapsed_buf));

        /* Proxy stats (verbose) */
        if (verbose && run_res->d.p_fwd + run_res->d.p_rev > 0) {
            char ps[192];
            snprintf(ps, sizeof ps, "proxy: %ld-> %ld<- pkts, dropped=%ld duped=%ld reordered=%ld corrupted=%ld truncated=%ld injected=%ld", run_res->d.p_fwd, run_res->d.p_rev, run_res->d.p_drop, run_res->d.p_dup, run_res->d.p_reorder, run_res->d.p_corrupt, run_res->d.p_trunc, run_res->d.p_inject);
            printf("         %s\n", DIM(ps));
        }

        /* Failure details */
        if (!run_res->ok) {
            if (run_res->d.client_exit || run_res->d.server_exit) {
                char ec[64];
                snprintf(ec, sizeof ec, "exit codes: client=%d, server=%d", run_res->d.client_exit, run_res->d.server_exit);
                printf("         %s\n", DIM(ec));
            }
            if (run_res->d.has_diff) {
                char fb[64]; snprintf(fb,sizeof fb,"first byte difference at offset %ld", run_res->d.first_diff);
                printf("         %s\n", DIM(fb));
            }
            if (run_res->d.input_sha[0]) {
                char s[80]; snprintf(s,sizeof s,"input  SHA-256: %.32s...", run_res->d.input_sha);
                printf("         %s\n", DIM(s));
            }
            if (run_res->d.output_sha[0]) {
                char s[80]; snprintf(s,sizeof s,"output SHA-256: %.32s...", run_res->d.output_sha);
                printf("         %s\n", DIM(s));
            }
            failed_names[n_failed_names++] = td->name;
            n_fail++;
        } else {
            n_pass++;
        }
        printf("\n");
    }

    // summary
    double total = now() - t0;
    char total_buf[32]; snprintf(total_buf, sizeof total_buf, "(%.1fs)", total);
    printf("  %s\n", DIM("\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"));

    // print inline
    printf("  %s ", BOLD("Results:"));
    printf("%s", GREEN(""));
    printf("%d passed", n_pass);
    if (n_fail) {
        printf(", %s", RED(""));
        printf("%d failed", n_fail);
    }
    if (n_skip) {
        printf(", %d skipped", n_skip);
    }
    printf("  %s\n", DIM(total_buf));

    if (n_failed_names > 0) {
        printf("  %s  ", RED("Failed:"));
        for (int i = 0; i < n_failed_names; i++) {
            printf("%s%s", failed_names[i], i+1<n_failed_names?", ":"");
        }
        printf("\n");
    }
    printf("\n");

    if (test_arg) {
        free((void *)test_arg);
    }
    free(run_res);
    free(failed_names);
    free(selected);
    free(abs_binary);

    return n_fail > 0 ? 1 : 0;
}