/*
 * (C) 2003-25 - ntop 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <pcap/pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256
pcap_t  *pd;
int verbose = 0;
struct pcap_stat pcapStats;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

//------------------------------Ashwani Start-------------------------------
#include <arpa/inet.h>
#include <stdint.h>
#include <ndpi_api.h>
#include <ndpi_main.h>

struct ndpi_detection_module_struct* ndpi_struct;

typedef struct {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t proto;
} FlowKey;

typedef struct {
    uint64_t src_bytes, dst_bytes;
    uint64_t src_pkts, dst_pkts;
    struct ndpi_flow_struct* ndpi_flow;
    u_int16_t detected_protocol;
} FlowStats;

#define MAX_FLOWS 10000
FlowKey flow_keys[MAX_FLOWS];
FlowStats flow_stats[MAX_FLOWS];
int flow_count = 0;

int compareFlowKeys(FlowKey* a, FlowKey* b) {
    return (a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
        a->src_port == b->src_port && a->dst_port == b->dst_port &&
        a->proto == b->proto);
}

int is_reverse_flow(FlowKey* a, FlowKey* b) {
	return (a->src_ip == b->dst_ip && a->dst_ip == b->src_ip &&
		a->src_port == b->dst_port && a->dst_port == b->src_port &&
		a->proto == b->proto);
}

uint32_t hashFlowKey(const FlowKey* key) {
	uint32_t hash = 17;
	hash = hash * 31 + key->src_ip;
	hash = hash * 31 + key->dst_ip;
	hash = hash * 31 + key->src_port;
	hash = hash * 31 + key->dst_port;
	hash = hash * 31 + key->proto;
	return hash;
}

void cleanup_ndpi() {
    if (ndpi_struct != NULL)
        ndpi_exit_detection_module(ndpi_struct);
}

void init_ndpi() {
    ndpi_struct = ndpi_init_detection_module( NULL);
    if (ndpi_struct == NULL) {
        fprintf(stderr, "ERROR: Could not initialize nDPI detection module\n");
        exit(EXIT_FAILURE);
    }

    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
    ndpi_set_bin(ndpi_struct, 1600);  // Typical MTU
    ndpi_finalize_initialization(ndpi_struct);
}

//------------------------------Ashwani End-------------------------------


static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth1" /* "e1000" */

int32_t gmt_to_local(time_t t);
char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);
int use_pcap_loop = 1;

volatile int do_shutdown = 0;

/* *************************************** */
/*
 * The time difference in microseconds
 */
long delta_time (struct timeval * now,
                 struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

void print_stats() {
  struct pcap_stat pcapStat;
  struct timeval endTime;
  float deltaSec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;
  char buf1[64], buf2[64];

  if(startTime.tv_sec == 0) {
    lastTime.tv_sec = 0;
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaSec = (double)delta_time(&endTime, &startTime)/1000000;

  if(pcap_stats(pd, &pcapStat) >= 0) {
    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped (%u if drops)]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_ifdrop, pcapStat.ps_recv-pcapStat.ps_drop,
	    pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop*100)/(double)pcapStat.ps_recv);
    fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000));

    if(lastTime.tv_sec > 0) {
      deltaSec = (double)delta_time(&endTime, &lastTime)/1000000;
      diff = numPkts-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
	      pfring_format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec*1000,
	      pfring_format_numbers(((double)diff/(double)(deltaSec)), buf2, sizeof(buf2), 1));
      lastPkts = numPkts;
    }

    fprintf(stderr, "=========================\n");
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;
  pcap_breakloop(pd);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* __intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

char* intoa(unsigned int addr) {
  return(__intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

static inline char* in6toa(struct in6_addr addr6) {
  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static int32_t thiszone;

void processPacket(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p) 
{
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    struct ip6_hdr ip6;

    int s = (h->ts.tv_sec + thiszone) % 86400;

    printf("%02d:%02d:%02d.%06u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec);

    memcpy(&ehdr, p, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);
    printf("[%s -> %s] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2));

    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }
    if(eth_type == 0x0800) {
      memcpy(&ip, p+sizeof(ehdr), sizeof(struct ip));
      // ----Ashwani Commented Start---------
      //printf("[%s]", proto2str(ip.ip_p));
      //printf("[%s ", intoa(ntohl(ip.ip_src.s_addr)));
      //printf("-> %s] ", intoa(ntohl(ip.ip_dst.s_addr)));
      // ----Ashwani Commented End

      //----Ashwani New Start------
      uint32_t src_ip = ntohl(ip.ip_src.s_addr);
      uint32_t dst_ip = ntohl(ip.ip_dst.s_addr);
      uint16_t src_port = 0, dst_port = 0;

      const u_char* l4 = p + sizeof(struct ether_header) + (ip.ip_hl << 2);

      if (ip.ip_p == IPPROTO_TCP || ip.ip_p == IPPROTO_UDP) {
          src_port = ntohs(*(uint16_t*)l4);
          dst_port = ntohs(*(uint16_t*)(l4 + 2));
      }

      FlowKey key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = ip.ip_p
      };

      int found = 0;
      uint32_t flow_id = hashFlowKey(&key);  // hashed flow ID

      for (int i = 0; i < flow_count; i++) 
      {
          if (compareFlowKeys(&key, &flow_keys[i])) {
              flow_stats[i].src_bytes += h->len;
              flow_stats[i].src_pkts++;
              found = 1;
              break;
          }
          else if (is_reverse_flow(&key, &flow_keys[i])) {
              flow_stats[i].dst_bytes += h->len;
              flow_stats[i].dst_pkts++;
              found = 1;
              break;
          }
      }

      if (!found && flow_count < MAX_FLOWS) {
          flow_keys[flow_count] = key;
          flow_stats[flow_count].src_bytes = h->len;
          flow_stats[flow_count].src_pkts = 1;
          flow_stats[flow_count].dst_bytes = 0;
          flow_stats[flow_count].dst_pkts = 0;
          flow_stats[flow_count].ndpi_flow = ndpi_flow_malloc(1000);
          flow_stats[flow_count].detected_protocol = NDPI_PROTOCOL_UNKNOWN;
          flow_count++;
      }

      // Run nDPI detection for this packet
      int flow_idx = -1;
      for (int i = 0; i < flow_count; i++) {
          if (compareFlowKeys(&key, &flow_keys[i]) || is_reverse_flow(&key, &flow_keys[i])) {
              flow_idx = i;
              break;
          }
      }

      if (flow_idx >= 0) {
          //struct ndpi_proto proto = ndpi_detection_process_packet(ndpi_struct,
          //    flow_stats[flow_idx].ndpi_flow,
          //    p + sizeof(struct ether_header),
          //    h->caplen - sizeof(struct ether_header),
          //    h->ts.tv_sec);

          //if (proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
          //    flow_stats[flow_idx].detected_protocol = proto.master_protocol;
      }

      // Print flow info
      for (int i = 0; i < flow_count; i++) {
          if (compareFlowKeys(&key, &flow_keys[i]) || is_reverse_flow(&key, &flow_keys[i])) {
              printf("\n\n---------- Flow Metadata ----------\n");
              //printf("Application Proto     : %s\n",ndpi_protocol2name(ndpi_struct, flow_stats[i].detected_protocol));
              printf("Flow ID Count         : %d\n", flow_count);;
              printf("Flow ID               : %u\n", hashFlowKey(&flow_keys[i]));
              printf("Protocol              : %s\n", proto2str(flow_keys[i].proto));

              printf("---------- Source -----------------\n");
              printf("Source IP      : %s\n", intoa(flow_keys[i].src_ip));
              printf("Source Port    : %u\n", flow_keys[i].src_port);
              printf("Packets Sent   : %lu\n", flow_stats[i].src_pkts);
              printf("Bytes Sent     : %lu\n", flow_stats[i].src_bytes);

              printf("---------- Destination ------------\n");
              printf("Destination IP  : %s\n", intoa(flow_keys[i].dst_ip));
              printf("Destination Port: %u\n", flow_keys[i].dst_port);
              printf("Packets Sent    : %lu\n", flow_stats[i].dst_pkts);
              printf("Bytes Sent      : %lu\n", flow_stats[i].dst_bytes);
              printf("-----------------------------------\n\n");
              break;
          }
      }


      //----Ashwani New End------
    } else if(eth_type == 0x86DD) {
      memcpy(&ip6, p+sizeof(ehdr), sizeof(struct ip6_hdr));
      // Ashwani
      //printf("[%s ", in6toa(ip6.ip6_src));
      //printf("-> %s] ", in6toa(ip6.ip6_dst));
    } else if(eth_type == 0x0806)
      printf("[ARP]");
    else
      printf("[eth_type=0x%04X]", eth_type);

    // ----Ashwani--comment out this line
    //printf("[caplen=%u][len=%u]\n", h->caplen, h->len);
  }

  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++, numBytes += h->len;

  if(verbose == 2) {
      int i;

      for(i = 0; i < h->caplen; i++)
        printf("%02X ", p[i]);
      printf("\n");
  }
 }

/* *************************************** */

void capturePackets() {
  u_char *pkt;
  struct pcap_pkthdr *h;
  int rc;

  while (!do_shutdown) {
    rc = pcap_next_ex(pd, &h, (const u_char **) &pkt);
    if (rc > 0) {
      processPacket(NULL, h, pkt);
    } else if (rc == 0) {
      /* No packets */
    } else /* rc < 0 */ {
      /* Error */
      break;
    }
  }
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("pcount\n(C) 2003-25 ntop\n");
  printf("-h              Print help\n");
  printf("-i <device>     Device name\n");
  printf("-f <filter>     pcap filter\n");
  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-l <len>        Capture length\n");
  printf("-S              Do not strip hw timestamps (if present)\n");
  printf("-v <mode>       Verbose (1: verbose, 2: very verbose)\n");

  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;

    printf("\nAvailable devices (-i):\n");
    while(devpointer) {
      printf(" %d. %s [%s]\n", i++, devpointer->name, devpointer->description);
      devpointer = devpointer->next;
    }

    pcap_freealldevs(devpointer);
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = "any", c, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  u_int8_t dont_strip_hw_ts = 0;
  int direction = PCAP_D_INOUT;

#if 0
  struct sched_param schedparam;

  schedparam.sched_priority = 99;
  if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
    printf("error while setting the scheduler, errno=%i\n",errno);
    exit(1);
  }

  mlockall(MCL_CURRENT|MCL_FUTURE);

#define TEST_PROCESSOR_AFFINITY
#ifdef TEST_PROCESSOR_AFFINITY
  {
   unsigned long new_mask = 1;
   unsigned int len = sizeof(new_mask);
   unsigned long cur_mask;
   pid_t p = 0; /* current process */
   int ret;

   ret = sched_getaffinity(p, len, NULL);
   printf(" sched_getaffinity = %d, len = %u\n", ret, len);

   ret = sched_getaffinity(p, len, &cur_mask);
   printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);

   ret = sched_setaffinity(p, len, &new_mask);
   printf(" sched_setaffinity = %d, new_mask = %08lx\n", ret, new_mask);

   ret = sched_getaffinity(p, len, &cur_mask);
   printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);
 }
#endif
#endif

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc,argv,"e:hi:l:v:f:S")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;
    case 'e':
      switch(atoi(optarg)) {
        case 0:
          direction = PCAP_D_INOUT;
        break;
        case 1:
          direction = PCAP_D_IN;
        break;
        case 2:
          direction = PCAP_D_OUT;
        break;
      }
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'v':
      verbose = atoi(optarg);
      break;
    case 'f':
      bpfFilter = strdup(optarg);
      break;
    case 'S':
      dont_strip_hw_ts = 1;
      break;
    }
  }

  init_ndpi();


  if(!dont_strip_hw_ts) setenv("PCAP_PF_RING_STRIP_HW_TIMESTAMP", "1", 1);

  printf("Capturing from %s, version is 05.04.2025.01\n", device);

  promisc = 1;

  pd = pcap_open_live(device, snaplen, promisc, 1000 /* ms */, errbuf);

  if (pd == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return(-1);
  }

  if(pcap_setdirection(pd, direction) != 0)
    printf("pcap_setdirection error: '%s'\n", pcap_geterr(pd));

  if(bpfFilter != NULL) {
    if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if(pcap_setfilter(pd, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
      pcap_freecode(&fcode);
    }
  }

  pcap_set_application_name(pd, "pcount");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pcap_set_watermark(pd, 128);

  if (use_pcap_loop)
    pcap_loop(pd, -1, processPacket, NULL);
  else
    capturePackets();

  print_stats();

  cleanup_ndpi();
  pcap_close(pd);

  return(0);
}
