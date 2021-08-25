/* 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# $Revision: $
# $Date: $
#
*/

// g++ ./udpgen.cc -o udpgen -lrt

// sample multicast tx/rx
// --tx --addr 224.1.1.1 --mcdev eth0 --ver --rate 10
// --rx --addr 224.1.1.1 --mcdev eth0 --ver
//
// samaple broadcast with large frames
// --tx --addr 1.1.1.255 --len 2000 --nodf --bc --ver
//
//
#define USEC_PER_SEC 1000000

#ifdef linux
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#else

#define _TIMEVAL_DEFINED

#define _WIN32_WINNT 0x0501

#include <winsock2.h>
#include <ws2tcpip.h>



const char * inet_ntop(int family,  struct sockaddr * sockaddr, char * buf, int buflen)
{
   struct sockaddr_in * sin;

   if(family == AF_INET)
    {
     sin = (struct sockaddr_in*) sockaddr;

     const char * p = inet_ntoa(sin->sin_addr);

     const int len = buflen >= (int)strlen(p) ? (int)strlen(p) : buflen;

     strncpy(buf, p, len);
   
     return buf;
    }
   else
    {
      return "";
    }
}

#define IP_MAXPACKET 0xffff
#define MAXTTL          255
#define MSG_DONTWAIT FIONBIO

struct timeval {
        long    tv_sec;
        long    tv_usec;
};

# define timercmp(a, b, CMP) 			      \
  (((a)->tv_sec == (b)->tv_sec) ? 		      \
   ((a)->tv_usec CMP (b)->tv_usec) : 		      \
   ((a)->tv_sec CMP (b)->tv_sec))

# define timeradd(a, b, result)			      \
  do {						      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;     \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;  \
    if ((result)->tv_usec >= USEC_PER_SEC)	      \
      {						      \
	++(result)->tv_sec;			      \
	(result)->tv_usec -= USEC_PER_SEC;	      \
      }						      \
  } while (0)

# define timersub(a, b, result)			      \
  do {						      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;  \
    if ((result)->tv_usec < 0) {		      \
      --(result)->tv_sec;			      \
      (result)->tv_usec += USEC_PER_SEC;	      \
    }						      \
  } while (0)

# define timerclear(a)                                \
  do {						      \
   (a)->tv_sec = (a)->tv_usec = 0;                    \
  } while(0)

#endif

# define timercopy(a, b) 		      \
  do {					      \
    (a)->tv_sec  = (b)->tv_sec; 	      \
    (a)->tv_usec = (b)->tv_usec;              \
  } while(0)

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include <vector>

typedef std::vector <double> LatencyVector;

LatencyVector rxLatencyVector;


enum WORKERMODE { MODE_NONE, MODE_RX, MODE_TX };

// prototypes
struct pktinfo_t {
 uint32_t seq_;
 struct timeval tv_;
}__attribute__((packed));

// ip v4/v6 addr
struct ipaddr_t {
  int family;
  union {
    struct sockaddr_in  v4;
    struct sockaddr_in6 v6;
  }sin __attribute__((packed));
}__attribute__((packed));

// mreq v4/v6 addr
struct maddr_t {
  int family;
  union {
    struct ip_mreq   m4;
    struct ipv6_mreq m6;
  }mreq __attribute__((packed));
}__attribute__((packed));

#ifdef linux
int  do_sched (const int, const int);
#endif

int  do_init(void);
void do_error (const char*);
void do_error_and_exit (const char*);
void do_sig (int);
void do_recv(void);
void do_recv_report(void);
int  do_send(void);
void do_send_report(void);
void do_bump(int, const struct pktinfo_t *, struct timeval * p2tv);
void show_report(void);
void show_sockinfo(void);
void show_bit_rate(void);
void set_current_delay(const clock_t);
void usage(const char *);
double get_bit_rate(const double);
void get_host_addr(struct ipaddr_t *, const char *);


short GET_SIN_PORT(struct ipaddr_t *x)
{
  if (x->family == AF_INET6) {
    return x->sin.v6.sin6_port;
  }
  else {
    return x->sin.v4.sin_port;
  }
}


void SET_SIN_PORT(struct ipaddr_t *x, unsigned short p)
{
  if(x->family == AF_INET6) {
    x->sin.v6.sin6_port = p;
  }
  else {
    x->sin.v4.sin_port = p;
  }
}


struct sockaddr* GET_SIN_ADDR(struct ipaddr_t *x)
{
  if (x->family == AF_INET6) {
    return (struct sockaddr*)&x->sin.v6.sin6_addr;
  }
  else {
    return (struct sockaddr*)&x->sin.v4.sin_addr;
  }
}


void SET_SIN_ADDR(struct ipaddr_t *x, const struct sockaddr *sa)
{
  if(x->family == AF_INET6){
    memcpy(&x->sin.v6.sin6_addr, &((struct sockaddr_in6*)&sa)->sin6_addr, 16);
  }
  else{
    memcpy(&x->sin.v4.sin_addr, &((struct sockaddr_in*)&sa)->sin_addr, 4);
  }
}


struct sockaddr* GET_SOCKADDR(struct ipaddr_t *x)
{
  if (x->family == AF_INET6) {
    return (struct sockaddr*)&x->sin.v6;
  }
  else {
    return (struct sockaddr*)&x->sin.v4;
  }
}


void SET_SOCKADDR(struct ipaddr_t *x, int f, const struct sockaddr *sa)
{
  if(f == AF_INET6){
    if(sa) {
      memcpy(&x->sin.v6.sin6_addr, &((struct sockaddr_in6*)sa)->sin6_addr, 16);
      x->sin.v6.sin6_family = f;
    }
  }
  else {
    if(sa) {
      memcpy(&x->sin.v4.sin_addr, &((struct sockaddr_in*)sa)->sin_addr, 4);
      x->sin.v4.sin_family = f;
    }
  } 

  x->family = f;
}


size_t GET_SOCKADDR_LEN(struct ipaddr_t *x)
{
  if (x->family == AF_INET6) {
    return sizeof(x->sin.v6);
  }
  else {
    return sizeof(x->sin.v4);
  }
}


int IS_MULTICAST_ADDR(struct ipaddr_t *x)
{
  if (x->family == AF_INET6) {
    return IN6_IS_ADDR_MULTICAST(x->sin.v6.sin6_addr.s6_addr);
  }
  else {
    return IN_MULTICAST(ntohl(x->sin.v4.sin_addr.s_addr));
  }
}


struct sockaddr* GET_MREQ(struct maddr_t *m)
{
  if (m->family == AF_INET6) {
    return (struct sockaddr*)&m->mreq.m6;
  }
  else {
    return (struct sockaddr*)&m->mreq.m4;
  }
}


size_t GET_MREQ_LEN(struct maddr_t *m)
{
  if (m->family == AF_INET6) {
    return sizeof(m->mreq.m6);
  }
  else {
    return sizeof(m->mreq.m4);
  }
}


void SET_MREQ_INTERFACE(struct maddr_t *m, unsigned int i)
{
  if(m->family == AF_INET6){
    m->mreq.m6.ipv6mr_interface = i;
  }
  else {
    m->mreq.m4.imr_interface.s_addr = i;
  } 
}


void SET_MREQ_GROUP(struct maddr_t *m, struct ipaddr_t *x)
{
  if(x->family == AF_INET6){
    memcpy(&m->mreq.m6.ipv6mr_multiaddr.s6_addr, &x->sin.v6.sin6_addr, sizeof(m->mreq.m6.ipv6mr_multiaddr.s6_addr));
  }
  else {
    m->mreq.m4.imr_multiaddr.s_addr = x->sin.v4.sin_addr.s_addr;
  } 

  m->family = x->family;
}


struct sockaddr* GET_MREQ_ADDR(struct maddr_t *m)
{
  if(m->family == AF_INET6){
    return (struct sockaddr*)&m->mreq.m6.ipv6mr_multiaddr;
  }
  else {
    return (struct sockaddr*)&m->mreq.m4.imr_multiaddr;
  } 
}



void get_host_addr(struct ipaddr_t *addr, const char *name)
{
  if(!name) {
    printf("error: bad addr %s\n", name);

    // fatal
    exit(EXIT_FAILURE);
  }
  else if(strncmp(name, "any", strlen("any")) == 0) {
    struct sockaddr sa;

    // clear
    memset(&sa, 0, sizeof(sa));

    SET_SOCKADDR(addr, AF_INET, &sa);

    return;
  }
  else {
    struct addrinfo *host = NULL;

    if (getaddrinfo(name, NULL, NULL, &host)) {
      printf("could not resolve hostname %s\n", name);

      // fatal
      exit(EXIT_FAILURE);
    }
    else {
      char str[64];
      SET_SOCKADDR(addr, host->ai_family, host->ai_addr);

      printf("name %s resolved to %s, family %d, len %d\n", 
            name, inet_ntop(addr->family, GET_SIN_ADDR(addr), str, sizeof(str)), host->ai_family, host->ai_addrlen);

      freeaddrinfo(host);
    }
  }
}

    
// globals
static  uint64_t  target_packet_count = ~0ULL;

static  size_t bytes_per_packet = 1000;
static  char   packet_buff[IP_MAXPACKET];

static  int verbose      = 0;
static  int sock         = -1;
static  int fd           = -1;
static  int opt          = 0;
static  int opt_index    = 0;
static  int opt_reuse    = 1;
static  int opt_bufsize  = IP_MAXPACKET;
static  int opt_rxdelay  = 0;
static  int opt_simple   = 0;
static  int opt_random   = 0;
static  int opt_rtp      = 0;
static  int opt_payload  = 0;
static  int opt_rxlv     = 0;
static char opt_val      = 0;

#ifdef linux
static  int priority         = 0;
static  int policy           = SCHED_RR;
static  int opt_dontfragment = IP_PMTUDISC_DO;
static  char mcdev[IFNAMSIZ] = "";
#endif

static  int sock_flags = 0;

static  int opt_broadcast = 0;
static  int opt_bsdcompat = 0;

static  char opt_ttl = MAXTTL;

static  float ramp_rate = 0.0;

static  char opt_tos    = 0;
static  char opt_mcloop = 0;

static  struct ipaddr_t saddr;
static  struct ipaddr_t bindaddr;

static  time_t current_delay  = USEC_PER_SEC;
static  time_t original_delay = USEC_PER_SEC;

static struct timeval tvStartTime;
static struct timeval tvLastPacket;
static struct timeval tvDelay;

static double latency_min;
static double latency_max;
static double latency_sum;

static uint64_t current_byte_count   = 0;
static uint32_t current_packet_count = 0;
static uint64_t timer_overruns       = 0;

static char current_action[256] = "none";

static enum WORKERMODE current_mode = MODE_NONE;

const char banner[5] = "-\\|/";

static char filename[256] = "";


void do_error(const char *str)
{
#ifdef WIN32
  int err = WSAGetLastError();
#else 
  int err = errno;
#endif
  fprintf(stderr, "%s:%s\n", str, strerror(err));

  close(sock);
}

void do_error_and_exit(const char *str)
{
  do_error(str);

  exit(EXIT_FAILURE);
}


// get time difference
inline double get_tv_diff (const struct timeval * t1, const struct timeval * t2)
{
  static struct timeval result;

  timersub(t2, t1, &result);

  return ((double)(result.tv_sec + (double)result.tv_usec / (double)USEC_PER_SEC));
}


// show usage
void
usage (const char *name)
{
  fprintf (stderr, "usage: %s --tx or --rx [option] \n", name);
  fprintf (stderr, "   --tx transmit\n");
  fprintf (stderr, "   --rx receive \n");

  fprintf (stderr, "\noptions: \n");
  fprintf (stderr, "   --port           send/recv port             default (12345)\n");
  fprintf (stderr, "   --addr           send/recv address          default (any)  \n");
  fprintf (stderr, "   --bindaddr       send bind address          default (any)  \n");
  fprintf (stderr, "   --bindport       send bind port             default (any)  \n");
  fprintf (stderr, "   --bc             enable broadcast           default (off)  \n");
  fprintf (stderr, "   --count          total packets to send      default (~0)   \n");
  fprintf (stderr, "   --len            length of packet to send   default (1000) \n");
  fprintf (stderr, "   --mcloop         enable multicast loopback  default (off)  \n");
  fprintf (stderr, "   --rate           rate per second, -1 flood  default (1)    \n");
  fprintf (stderr, "   --simple         simple recv mode           default (off)  \n");
  fprintf (stderr, "   --tos            ip tos (0-255)             default (0)    \n");
  fprintf (stderr, "   --ttl            ip ttl (0-255)             default (255)  \n");
  fprintf (stderr, "   --ramp           ramp up percent (0.0-1.0)  default (0.0)  \n");
  fprintf (stderr, "   --verbose        verbose output             default (off)  \n");
  fprintf (stderr, "   --noblock        do not block on socket io  default (off)  \n");
  fprintf (stderr, "   --random         set packet payload random  default (off)  \n");
  fprintf (stderr, "   --rtp            set packet payload as rtp  default (off)  \n");
  fprintf (stderr, "   --bufsize        set socket buf size        default (%d)  \n", IP_MAXPACKET);
  fprintf (stderr, "   --rxdelay        set rx delay in msec       default (0)   \n");
  fprintf (stderr, "   --val            set the payload val        default (0)   \n");
  fprintf (stderr, "   --rxlv           enable rx latency vector   default (0)   \n");

#ifdef linux
  fprintf (stderr, "   --mcdev          mc outgoing interface      default (any)  \n");
  fprintf (stderr, "   --nodf           disable do not fragment    default (on)   \n");
  fprintf (stderr, "   --bsd            enable BSD compatible      default (off)  \n");
  fprintf (stderr, "   --rt             process sched priority     default (0)    \n");
  fprintf (stderr, "   --fifo           process sched policy       default (rr)   \n");
#endif

  fprintf (stderr, "   --file           io file                    default (none) \n");
  fprintf (stderr, "   --help           print this list                           \n");

  fprintf (stderr, "\nexample: \n");
  fprintf (stderr, "./udpgen --tx --addr localhost --rate 1000 --len 1000 --ramp 0.01 --ver --rt 1 --fifo\n");
  fprintf (stderr, "./udpgen --rx --ver        \n");
}


#ifdef linux
int do_sched (const int priority, const int policy)
{
  int min = sched_get_priority_min(policy);
  int max = sched_get_priority_max(policy);

  // check priority range
  if(priority >= min && priority <= max) {
    struct sched_param sp = {priority};

    // set prioirty
    if(sched_setscheduler(0, policy, &sp) < 0) {
      do_error_and_exit("sched");
    }
  }  
  else {
    fprintf (stderr, "priority (%d) not within range [%d - %d]\n",
             priority, min, max);

    return -1;
  }

  return 0;
}
#endif


// set current delay
inline void set_current_delay(const clock_t usec_delay)
{
  if(usec_delay == 0)
   {
    // seconds to wait
    tvDelay.tv_sec  = 0;

    // u_seconds to wait, minimum of 1 usec
    tvDelay.tv_usec = 1;
   }
  else
   {
    // seconds to wait
    tvDelay.tv_sec  = usec_delay / USEC_PER_SEC;

    // u_seconds to wait
    tvDelay.tv_usec = usec_delay % USEC_PER_SEC;
   }
}


// get current bit rate
inline double get_bit_rate(const double et)
{
   return  (current_packet_count > 1 ? (double) (et ? (current_byte_count * 8.0) / (et * 1000.0) : 0.0) : 0.0);
}


// show what happened
inline void show_report()
{
  const double et = get_tv_diff(&tvStartTime, &tvLastPacket);
  const double rate = get_bit_rate(et);
  char str[64];

  fprintf (stderr, "\n%s %4u pkts, %5llu bytes, time %0.4f, %5.2f %s, latency min/avg/max %6.4lf/%6.4lf/%6.4lf ms, timer overruns %llu,", 
           current_action, 
           current_packet_count, 
           current_byte_count, 
           et, 
           rate >= 1000.0 ? rate / 1000.0 : rate,
           rate >= 1000.0 ? "Mbps" : "Kbps",
           latency_min * 1000.0,
           latency_sum / (current_packet_count > 0 ? current_packet_count : 1) * 1000.0,
           latency_max * 1000.0,
           timer_overruns);

  if(current_mode == MODE_RX) {
    fprintf (stderr, " from %s:%hu\n", inet_ntop(saddr.family, GET_SIN_ADDR(&saddr), str, sizeof(str)), htons(GET_SIN_PORT(&saddr)));

    for(LatencyVector::iterator iter = rxLatencyVector.begin(); iter != rxLatencyVector.end(); ++iter)
     {
       fprintf (stderr, "latency %8.6lf s\n", *iter);
     }
  }

  if(current_mode == MODE_TX) {
    fprintf (stderr, " to %s:%hu\n",   inet_ntop(saddr.family, GET_SIN_ADDR(&saddr), str, sizeof(str)), htons(GET_SIN_PORT(&saddr)));
  }
}


// show current bit rate
inline void show_bit_rate()
{
  const double rate = get_bit_rate(get_tv_diff(&tvStartTime, &tvLastPacket));
  static unsigned char tick = 0;

  fprintf (stderr, "%c %6.3f %s\r", 
       banner[tick++ % 4], 
       rate >= 1000.0 ? rate / 1000.0 : rate,
       rate >= 1000.0 ? "Mbps" : "Kbps");
}



// signal handler
void do_sig (int sig_num)
{
  switch(sig_num) {
    case SIGINT:
    case SIGTERM:
      show_report();

      // done
      exit (EXIT_SUCCESS);
  }
}


// bump stats and tx rate
inline void do_bump(int result, const struct pktinfo_t* pinfo, struct timeval * p2tv)
{
   // remember last time
   static struct timeval tvlast = { 0, 0 };

   if(ntohl(pinfo->seq_) == 0)
    {
      current_packet_count = 0;

      current_byte_count = 0;

      timerclear(&tvlast);
    }

   // mark time at first pkt
   if(current_packet_count == 0) {
     // set start to current time
     timercopy(&tvStartTime, p2tv);

     // set stop to current time
     timercopy(&tvLastPacket, &tvStartTime);
   }
   else {
     // save time of last packet
     timercopy(&tvLastPacket, p2tv);
   }

   // packet letency
   double latency = get_tv_diff(&(pinfo->tv_), &tvLastPacket);

   if(opt_rxlv)
    {
      rxLatencyVector.push_back(latency);
    }

   // first packet set min/max
   if(current_packet_count == 0) {
     latency_min = latency;
     latency_max = latency;
     latency_sum = 0;
    }
   else {
     // lower
     if(latency < latency_min) {
       latency_min = latency;
     }

     // higher
     if(latency > latency_max) {
       latency_max = latency;
     }
   }

   // sum
   latency_sum += latency;

   // bump byte count
   current_byte_count += result;

   // bump packet count
   ++current_packet_count; 

   // time to udpate
   if(timercmp(&tvlast, &tvLastPacket, <)) {

     // adjust packet rate
     if(ramp_rate != 0.0) {
       static clock_t adjustment = 0;

       // get percentage of the original delay
       adjustment = ramp_rate * original_delay;

       // adjust time, do not go below 0
       current_delay -= (adjustment < current_delay) ? adjustment : 0;

       // reset delay
       set_current_delay(current_delay);
     }

     // verbose only on update
     if(verbose)
       show_bit_rate();

     // reset last time to now
     timercopy(&tvlast, &tvLastPacket);
   }
}



// show our socket info
void show_sockinfo()
{
  struct sockaddr sa;
  struct ipaddr_t addr;

  char str[64];

  // clear
  memset(&sa, 0, sizeof(sa));
  memset(&addr, 0, sizeof(addr));

  // socklen
  socklen_t socklen = sizeof(sa);

  // sock stats
  getsockname (sock, &sa, &socklen);

  SET_SOCKADDR(&addr, sa.sa_family, &sa);

  SET_SIN_PORT(&addr, ((struct sockaddr_in*)&sa)->sin_port);

  printf ("%s on socket family %u, len %u, bound to %s:%hu\n", 
           current_action, addr.family, socklen, 
           inet_ntop (addr.family, GET_SIN_ADDR(&addr), str, sizeof(str)), ntohs(GET_SIN_PORT(&addr)));
}


// initialze socket
int do_init()
{
  if(sock != -1)
   {
     close(sock);
   }

  // the socket
  if ((sock = socket (saddr.family, SOCK_DGRAM, 0)) < 0) {
    do_error_and_exit ("socket");
  }

  // reuse 
  if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt_reuse, sizeof (opt_reuse)) < 0) {
    do_error_and_exit ("setsockopt:SO_REUSEADDR");
  }

#ifdef linux
  // set sched priority/policy
  if(priority > 0) {
    if(do_sched (priority, policy) < 0) {
      return -1;
    }
  }
#endif

  // set the current rate
  set_current_delay(current_delay);

  // remember original delay
  original_delay = current_delay;

  // receive mode
  if(current_mode == MODE_RX) {

     // read output file
     if(strlen(filename) > 0) {
       if((fd = open(filename, O_CREAT | O_WRONLY)) < 0) {
          do_error_and_exit("open");
        }
      }

      // action mode
      strcpy(current_action, "recv");
 
      // listen for multicast
      if (IS_MULTICAST_ADDR(&saddr)) {
          struct maddr_t mreq;

          // clear
          memset(&mreq, 0, sizeof(mreq));

          // group
          SET_MREQ_GROUP(&mreq, &saddr);

#ifdef linux
          if(strlen(mcdev)) {
            struct ifreq ifr;

            // clear
            memset(&ifr, 0, sizeof(ifr));

            strncpy(ifr.ifr_name, mcdev, IFNAMSIZ);

            if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
              do_error_and_exit("ioctl:SIOCGIFADDR");
            } 

            SET_MREQ_INTERFACE(&mreq, ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
         }
#endif

          // a little info on when/why to bind.
          // Receive
          // We always need to bind a port number to the receive socket so we can receive the service (port) we are
          // interested in. Usually INADDR_ANY is used for the address, this means we do not care about the
          // ip dst addr of the datagram. To limit the delivery of datagams we can also specify
          // the interface addr for unicast or the group addr for multicast this will force a match
          // on dst port and dst address of the datagram. 

          // For multicast note that an interface needs to be placed in
          // multicast accept/listent mode for a particular group else it wiil not advance past layer 2. Once the datagram
          // makes its way into the stack any listener on any interface MAY receive the datagram based on the bind
          // rules above.

          // Send
          // When we bind a send socket we are telling the kernel what ip src addr and src port we want to use.
          // The kernel should enforce certiain rules about what source addresses are vaild for that interface 
          // example, 0.0.0.0, multicast, broadcast are not valid source addresses. In most cases you can can specify the
          // address of any interface on the system, even if routing will push the packet another interface.
          // If we do not bind then the kerenl will bind for us using an arbitray port 
          // number and ip src address that matches the outgoing interface.

         
          // bind the socket to the grp/port pair. 
          if (bind (sock, GET_SOCKADDR(&saddr), GET_SOCKADDR_LEN(&saddr)) < 0) {
             do_error_and_exit ("bind");
          }

          // add membership 
          if (setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)GET_MREQ(&mreq), GET_MREQ_LEN(&mreq)) < 0) {
              do_error_and_exit("setsockopt:IP_ADD_MEMBERSHIP");
          }
          else {
              char str[64];
              printf("joined group %s\n", inet_ntop (mreq.family, GET_MREQ_ADDR(&mreq), str, sizeof(str)));
          }
      }
      else {
        // bind 
        if (bind (sock, GET_SOCKADDR(&saddr), GET_SOCKADDR_LEN(&saddr)) < 0) {
           do_error_and_exit ("bind");
        }
      }

    // rxbuf size 
    if (setsockopt (sock, SOL_SOCKET, SO_RCVBUF, (char*)&opt_bufsize, sizeof (opt_bufsize)) < 0) {
      do_error_and_exit ("setsockopt:SO_RCVBUF");
    }
  }
  // send mode 
  else if(current_mode == MODE_TX) {

      // read input file
      if(strlen(filename) > 0) {

        if((fd = open(filename, O_RDONLY)) < 0) {
          do_error_and_exit("open");
        }
        else {
          struct stat st;

          if(fstat(fd, &st) < 0) {
            do_error_and_exit("stat");
          }

          if(read(fd, packet_buff, st.st_size) < 0) {
            do_error_and_exit("read");
          }
        }
      }

      // bind 
      if (bind (sock, GET_SOCKADDR(&bindaddr), GET_SOCKADDR_LEN(&bindaddr)) < 0) {
          do_error_and_exit ("bind");
      }

      // action mode 
      strcpy(current_action, "send");

      // broadcast 
      if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST, (char*)&opt_broadcast, sizeof (opt_broadcast)) < 0) {
          do_error_and_exit ("setsockopt:SO_BROADCAST");
      }

#ifdef linux
      // bsd compat 
      if (setsockopt (sock, SOL_SOCKET, SO_BSDCOMPAT, (char*)&opt_bsdcompat, sizeof (opt_bsdcompat)) < 0) {
          do_error_and_exit ("setsockopt:SO_BSDCOMPAT");
      }
#endif

      // tos 
      if (setsockopt (sock, IPPROTO_IP, IP_TOS, (char*)&opt_tos, sizeof (opt_tos)) < 0) {
          do_error_and_exit ("setsockopt:IP_TOS");
      }

#ifdef linux
      // mtu 
      if (setsockopt (sock, IPPROTO_IP, IP_MTU_DISCOVER, (char*)&opt_dontfragment, sizeof (opt_dontfragment)) < 0) {
          do_error_and_exit ("setsockopt:IP_MTU_DISCOVER");
      }
#endif
      // ttl 
      if (setsockopt (sock, IPPROTO_IP, IP_TTL, (char*)&opt_ttl, sizeof (opt_ttl)) < 0) {
          do_error_and_exit ("setsockopt:IP_TTL");
      }

      // txbuf size 
      if (setsockopt (sock, SOL_SOCKET, SO_SNDBUF, (char*)&opt_bufsize, sizeof (opt_bufsize)) < 0) {
          do_error_and_exit ("setsockopt:SO_SNDBUF");
      }


      // multicast 
      if (IS_MULTICAST_ADDR(&saddr)) {

          // mc ttl 
          if (setsockopt (sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&opt_ttl, sizeof (opt_ttl)) < 0) {
              do_error_and_exit ("setsockopt:IP_MULTICAST_TTL");
          }

          // mc loop 
          if (setsockopt (sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&opt_mcloop, sizeof (opt_mcloop)) < 0) {
             do_error_and_exit ("setsockopt:IP_MULTICAST_LOOP");
          }

#ifdef linux
          if(strlen(mcdev)) {
            struct ip_mreqn mreqn;
            struct ifreq ifr;

            // clear
            memset(&mreqn, 0, sizeof(mreqn));
            memset(&ifr,  0, sizeof(ifr));

            strncpy(ifr.ifr_name, mcdev, IFNAMSIZ);

            if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
              do_error_and_exit("ioctl:SIOCGIFADDR");
            } 
            else {
              mreqn.imr_multiaddr.s_addr = 0;
              mreqn.imr_address.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
            }

            if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
              do_error_and_exit("ioctl:SIOCGIFINDEX");
            } 
            else {
              mreqn.imr_ifindex = ifr.ifr_ifindex;
            }

            if(setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) < 0) {
              do_error_and_exit("setsockopt:IP_MULTICAST_IF");
            }
         }
#endif
      }
  }
  else {
      // problem
      return -1;
  }

  // all ok 
  return 0;
}


// blocking wait
inline void do_wait_timerfd (const int fd)
{
  const int nfd = fd + 1;

  fd_set fdset;

  FD_ZERO (&fdset);

  FD_SET (fd, &fdset);

  const int numset = select (nfd, &fdset, 0, 0, NULL);

  if (numset <= 0) 
   {
     perror ("select:");
   }

  if (FD_ISSET (fd, &fdset)) 
   {
     uint64_t val;

     if(read(fd, &val, sizeof(val)) != sizeof(val))
      {
         perror ("read:");
      }

     if(val > 1)
      {
        timer_overruns += val;
      }
   }
}



// receive function
void do_recv()
{
  struct pktinfo_t *pinfo = (struct pktinfo_t*) packet_buff;

  // sizeof remote
  socklen_t socklen = GET_SOCKADDR_LEN(&saddr);

  // show socket info
  show_sockinfo();

  struct timeval tvRxTime;

  // forever or target reached
  while(!current_packet_count || (current_packet_count < target_packet_count)) {
     fd_set  bits;

     // reset fd set
     FD_ZERO(&bits);
     FD_SET((unsigned int)sock, &bits);

     // wait here, wakes on signal or socket is ready 
     if(select(sock + 1, &bits, NULL, NULL, NULL) <= 0) {
       continue;
     }

     int result = recvfrom(sock, packet_buff, sizeof(packet_buff), sock_flags, GET_SOCKADDR(&saddr), &socklen);

     gettimeofday(&tvRxTime, NULL);

     // recv error
     if(result < 0) {
       do_error_and_exit ("recvfrom");
     }
     else {
       if(opt_simple) {
          char str[64];
          fprintf (stderr, "recv pkt len %d, from %s:%hu\n", 
                   result, inet_ntop(saddr.family, GET_SIN_ADDR(&saddr), str, sizeof(str)), htons(GET_SIN_PORT(&saddr)));
       }  
       else {
         // bump stats
         do_bump(result, pinfo, &tvRxTime);
       }

       if(fd >= 0) {
         if(write(fd, packet_buff, result) < 0) {
           do_error_and_exit("write");
         }
       }
     }

     if(opt_rxdelay)
      {
        usleep(opt_rxdelay * 1000);
      }
  }

  // done
  return;
}



// send function
int do_send()
{
  struct pktinfo_t *pinfo = (struct pktinfo_t*) packet_buff;
  
  size_t i;

  unsigned char ch = 0;

  int timerfd = -1;

  // show socket info
  show_sockinfo();

  for(i = sizeof(*pinfo); i < sizeof(packet_buff); ++i) {
    if(opt_payload)
     {
       packet_buff[i] = opt_val;
     }
    else
     {
       packet_buff[i] = ch++;
     }
  }

  timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

  if(timerfd < 0)
   {
     do_error_and_exit("timerfd_create:");
   }

  struct itimerspec timspec;

  bzero(&timspec, sizeof(timspec));

  // interval
  timspec.it_interval.tv_sec  = tvDelay.tv_sec;
  timspec.it_interval.tv_nsec = tvDelay.tv_usec * 1000;

  // start time in 1 usec
  timspec.it_value.tv_sec  = 0;
  timspec.it_value.tv_nsec = 1000;

  const int res = timerfd_settime(timerfd, 0, &timspec, NULL);

  if(res < 0)
   {
     do_error_and_exit("timerfd_settime");
   }

  // forever or target reached
  while(!current_packet_count || (current_packet_count < target_packet_count)) {
     if(opt_random) {
       struct timeval tvr;
       gettimeofday(&tvr, NULL);
       srandom(tvr.tv_usec);

       for(i = sizeof(*pinfo); i < sizeof(packet_buff); ++i) {
          packet_buff[i] = (unsigned char) (random() & 0xFF);
        }
     }

     if(opt_rtp) {
        // rtp v2
        packet_buff[0] = 0x80;
     } 
     else {
        // apply packet count TODO net byte order
        pinfo->seq_ = htonl(current_packet_count);
     }

     // TODO net byte order
     gettimeofday(&(pinfo->tv_), NULL);
     
     int result = sendto(sock, packet_buff, bytes_per_packet, sock_flags, GET_SOCKADDR(&saddr), GET_SOCKADDR_LEN(&saddr));

     // send error
     if(result < 0) {
       if(errno != EAGAIN)
         {
           do_error("sendto");

          return -1;
         }
     }
     else {
       // bump stats
       do_bump(result, pinfo, &pinfo->tv_);
     }

     // delay here     
     do_wait_timerfd(timerfd);
  }

  close(timerfd);

  // done
  return 0;
}



int
main (int argc, char *argv[])
{
  // our options
  struct option opts[] = {
    {"help",         0, 0, 0},
    {"addr",         1, 0, 1},
    {"port",         1, 0, 2},
    {"tx",           0, 0, 3},
    {"rx",           0, 0, 4},
    {"bc",           0, 0, 5},
    {"bsd",          0, 0, 6},
    {"count",        1, 0, 7},
    {"len",          1, 0, 8},
    {"mcloop",       0, 0, 9},
    {"nodf",         0, 0, 10},
    {"rate",         1, 0, 11},
    {"tos",          1, 0, 12},
    {"ttl",          1, 0, 13},
    {"ramp",         1, 0, 14},
    {"verbose",      0, 0, 15},
    {"noblock",      0, 0, 16},
    {"rt",           1, 0, 17},
    {"fifo",         0, 0, 18},
    {"file",         1, 0, 19},
    {"mcdev",        1, 0, 20},
    {"bindaddr",     1, 0, 21},
    {"bindport",     1, 0, 22},
    {"reuse",        1, 0, 23},
    {"simple",       1, 0, 24},
    {"random",       0, 0, 25},
    {"bufsize",      1, 0, 26},
    {"rxdelay",      1, 0, 27},
    {"rtp",          0, 0, 28},
    {"val",          1, 0, 29},
    {"rxlv",         0, 0, 30},
    { NULL,          0, 0, 0}
  };

  // signal catchers
  signal (SIGINT,  do_sig);
  signal (SIGTERM, do_sig);

  // clear
  memset(&saddr,0,sizeof(saddr));
  memset(&bindaddr,0,sizeof(bindaddr));

  // default dst port
  SET_SIN_PORT(&saddr, htons(12345));

  // default family
  SET_SOCKADDR(&bindaddr, AF_INET, NULL);

#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;

    wVersionRequested = MAKEWORD(2, 2);

    WSAStartup(wVersionRequested, &wsaData);
#endif

  // get command line opts 
  while ((opt = getopt_long (argc, argv, "", opts, &opt_index)) != EOF) {
    switch (opt) {

    // dest addr 
    case 1:
      get_host_addr(&saddr, optarg);
      break;

    // dest port 
    case 2:
      SET_SIN_PORT(&saddr, htons(atoi (optarg)));
      break;

    // tx mode
    case 3:
      current_mode = MODE_TX;
      break;

    // rx mode
    case 4:
      current_mode = MODE_RX;
      break;

    // broadcast flag 
    case 5:
      opt_broadcast = 1;
      break;

    // bsd compat flag 
    case 6:
      opt_bsdcompat = 1;
      break;

    // total pkts to process 
    case 7:
      target_packet_count = atoll (optarg);
      break;

    // bytes per pkt 
    case 8:
      bytes_per_packet = atoi (optarg);

      if(bytes_per_packet > IP_MAXPACKET) {
         bytes_per_packet = IP_MAXPACKET;
      }
      break;

    // mc loop flag 
    case 9:
      opt_mcloop = 1;
      break;

#ifdef linux
    // fragment flag 
    case 10:
      opt_dontfragment = IP_PMTUDISC_DONT;
      break;
#endif

    // tx pkt rate 
    case 11: {
      const float packet_rate = atof (optarg);

      if (packet_rate > 0.0) {
        current_delay = (time_t)(USEC_PER_SEC / packet_rate);
      }
      else {
        current_delay = 0;
      }
     }
      break;
 
    // tos 
    case 12:
      opt_tos = atoi (optarg) & 0xFF;
      break;

    // ttl 
    case 13:
      opt_ttl = atoi (optarg) & 0xFF;
      break;

    // ramp 
    case 14:
      ramp_rate = atof (optarg);

      if(ramp_rate < 0.0 || ramp_rate > 1.0) {
        ramp_rate = 0.0;
      }
      break;

    // verbose 
    case 15:
      verbose = 1;
      break;

    // no block 
    case 16:
      sock_flags |= MSG_DONTWAIT;
      break;

#ifdef linux
    // priority
    case 17:
      priority = atoi(optarg);
      break;

    // policy fifo
    case 18:
      policy = SCHED_FIFO; 
      break;
#endif

    //  io file
    case 19:
      strncpy(filename, optarg, sizeof(filename)); 
      break;

#ifdef linux
    //  mc dev
    case 20:
      strncpy(mcdev, optarg, sizeof(mcdev)); 
      break;
#endif

    // bind addr 
    case 21:
      get_host_addr(&bindaddr, optarg);
      break;

    // bind port 
    case 22:
      SET_SIN_PORT(&bindaddr, htons(atoi (optarg)));
      break;

    // reuse flag
    case 23:
      opt_reuse = atoi(optarg);
      break;

    // simple flag
    case 24:
      opt_simple = 1;
      break;

    // random flag
    case 25:
      opt_random = 1;
      break;

    // bufsize
    case 26:
      opt_bufsize = atoi(optarg);
      break;

    // rxdelay
    case 27:
      opt_rxdelay = atoi(optarg);
      break;

    // rtp flag
    case 28:
      opt_rtp = 1;
      break;

    // payload val
    case 29:
      opt_payload = 1;
      opt_val = atoi(optarg);
      break;

    // rx latency vector
    case 30:
      opt_rxlv = 1;
      break;

    // help 
    case 0:
    default:
      usage (argv[0]);
      exit (EXIT_FAILURE);
    }
  }

  // listener
  if(current_mode == MODE_RX) {
    if(do_init() == 0) {
      do_recv();
    }
  }
  // sender
  else if(current_mode == MODE_TX) {
    int r = -1;

    while(r == -1) {
      if(do_init() == 0) {
        r = do_send();
      }
    }
  }
  // fatal
  else {
     printf("no mode set, use --tx or --rx\n");
     usage(argv[0]);
     exit (EXIT_FAILURE);
  }

  // show final stats
  show_report();

  // cleanup 
  close (sock);

  // done
  return (EXIT_SUCCESS);
}
