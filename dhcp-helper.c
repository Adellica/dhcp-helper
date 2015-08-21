/* dhcp-helper is Copyright (c) 2004 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: simon@thekelleys.org.uk */

#define VERSION "0.2"

#define COPYRIGHT "Copyright (C) 2004 Simon Kelley" 

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <limits.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <linux/sockios.h>

#define PIDFILE "/var/run/dhcp-helper.pid"
#define USER "nobody"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define BOOTREQUEST      1
#define BOOTREPLY        2

struct namelist {
  char name[IF_NAMESIZE];
  struct in_addr addr;
  struct namelist *next;
};

struct interface {
  int index;
  struct in_addr addr;
  struct interface *next;
};

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct udp_dhcp_packet {
  struct ip ip;
  struct udphdr {
    u16 uh_sport;               /* source port */
    u16 uh_dport;               /* destination port */
    u16 uh_ulen;                /* udp length */
    u16 uh_sum;                 /* udp checksum */
  } udp;
  struct dhcp_packet {
    u8 op, htype, hlen, hops;
    u32 xid;
    u16 secs, flags;
    struct in_addr ciaddr, yiaddr, siaddr, giaddr;
    u8 chaddr[16], sname[64], file[128];
    u8 options[312];
  } data;
};


int main(int argc, char **argv)
{
  int fd = -1, rawfd, opt, flags;
  struct ifreq ifr;
  struct sockaddr_in saddr;
  unsigned int buf_size = sizeof(struct udp_dhcp_packet);
  struct udp_dhcp_packet *rawpacket;
  struct namelist *interfaces = NULL, *except = NULL;
  struct interface *ifaces = NULL;
  struct namelist *servers = NULL;
  char *runfile = PIDFILE;
  char *user = USER;
  int debug = 0;
  
  while (1)
    {
      int option = getopt(argc, argv, "b:e:i:s:u:r:dv");
      
      if (option == -1)
	break;

      switch (option) 
	{
	case 's': case 'b': case 'i': case 'e':
	  {
	    struct namelist *new = malloc(sizeof(struct namelist));
	    
	    if (!new)
	      {
		fprintf(stderr, "dhcp-helper: cannot get memory\n");
		exit(1);
	      }
	    
	    strncpy(new->name, optarg, IF_NAMESIZE);
	    strncpy(ifr.ifr_name, optarg, IF_NAMESIZE);
	    new->addr.s_addr = 0;

	    if (option == 's')
	      {
		struct hostent *e = gethostbyname(optarg);
		
		if (!e)
		  {
		    fprintf(stderr, "dhcp-helper: cannot resolve server name %s\n", optarg);
		    exit(1);
		  }
		new->addr = *((struct in_addr *)e->h_addr);
	      } 
	    else if (strlen(optarg) > IF_NAMESIZE)
	      {
		fprintf(stderr, "dhcp-helper: interface name too long: %s\n", optarg);
		exit(1);
	      }
	    else if ((fd == -1 && (fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) ||
		     ioctl (fd, SIOCGIFFLAGS, &ifr) == -1)
	      {
		fprintf(stderr, "dhcp-helper: bad interface %s: %s\n", optarg, strerror(errno));
		exit (1);
	      }
	    else if (option == 'b' && !(ifr.ifr_flags & IFF_BROADCAST))
	      {
		fprintf(stderr, "dhcp-helper: interface %s cannot broadcast\n", optarg);
		exit(1);
	      }
	    
	    if (option == 'i')
	      {
		new->next = interfaces;
		interfaces = new;
	      }
	    else if (option == 'e')
	      {
		new->next = except;
		except = new;
	      }
	    else
	      {
		new->next = servers;
		servers = new;
	      }
	  }
	  break;
	  
	case 'u':
	  if ((user = malloc(strlen(optarg) + 1)))
	    strcpy(user, optarg);
	  break;

	case 'r':
	  if ((runfile = malloc(strlen(optarg) + 1)))
	    strcpy(runfile, optarg);
	  break;
	  
	case 'd':
	  debug = 1;
	  break;
	  
	case 'v':
	  fprintf(stderr, "dhcp-helper version %s, %s\n", VERSION, COPYRIGHT);
	  exit(0);
	  
	default:
	  fprintf(stderr, 
		  "Usage: dhcp-helper [OPTIONS]\n"
		  "Options are:\n"
		  "-s <server>      Forward DHCP requests to <server>\n"
		  "-b <interface>   Forward DHCP requests as broadcasts via <interface>\n"
                  "-i <interface>   Listen for DHCP requests on <interface>\n"
		  "-e <interface>   Do not listen for DHCP requests on <interface>\n"
		  "-u <user>        Change to user <user> (defaults to %s)\n"
		  "-r <file>        Write daemon PID to this file (default %s)\n"
		  "-d               Debug mode\n"
		  "-v               Give version and copyright info and then exit\n",
		  USER, PIDFILE);
	  exit(1);
	  
	}
    }

  if (!servers)
    {
      fprintf(stderr, "dhcp-helper: no destination specifed; give at least -s or -b option.\n");
      exit(1); 
    }

  if (!(rawpacket = malloc(buf_size)))
    {
      perror("dhcp-helper: cannot allocate buffer");
      exit(1);
    }
  
  if (fd == -1 && (fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    {
      perror("dhcp-helper: cannot create socket");
      exit(1);
    }
  
  opt = 1;
  if ((flags = fcntl(fd, F_GETFL, 0)) == -1 ||
      fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
      setsockopt(fd, SOL_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) == -1)  
    {
      perror("dhcp-helper: cannot set options on DHCP socket");
      exit(1);
    }
  
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(DHCP_SERVER_PORT);
  saddr.sin_addr.s_addr = INADDR_ANY;
  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)))
    {
      perror("dhcp-helper: cannot bind DHCP server socket");
      exit(1);
    }

  if ((rawfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_IP))) == -1)
    {
      perror("dhcp-helper: cannot create DHCP packet socket");
      exit(1);
    }

  if (setsockopt(rawfd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
    {
      perror("dhcp-helper: cannot set options on DHCP packet socket");
      exit(1);
    }

  if (!debug)
    {
      FILE *pidfile;
      struct passwd *ent_pw = getpwnam(user);
      int i;
      gid_t dummy;
      struct group *gp;
      
      if (!ent_pw)
	{
	  fprintf(stderr, "dhcp-helper: cannot find user %s\n", user);
	  exit(1);
	};
      
      /* The following code "daemonizes" the process. 
         See Stevens section 12.4 */

      if (fork() != 0 )
        exit(0);
      
      setsid();
      
      if (fork() != 0)
        exit(0);
      
      chdir("/");
      umask(022); /* make pidfile 0644 */
      
      /* write pidfile _after_ forking ! */
      if ((pidfile = fopen(runfile, "w")))
        {
          fprintf(pidfile, "%d\n", (int) getpid());
          fclose(pidfile);
        }
      
      umask(0);

      for (i=0; i<64; i++)        
	if (i != rawfd && i != fd)
	  close(i);

      setgroups(0, &dummy);

      if ((gp = getgrgid(ent_pw->pw_gid)))
	setgid(gp->gr_gid);
      setuid(ent_pw->pw_uid);
    }
  
  while (1) {
    fd_set rset;
    int iface_index;
    struct in_addr iface_addr;
    unsigned int sz, size;    
    struct dhcp_packet *header;
    struct msghdr msg;
    struct iovec iov[1];
    struct cmsghdr *cmptr;
    union {
      struct cmsghdr align; /* this ensures alignment */
      char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
    } control_u;
    
    FD_ZERO(&rset);
    FD_SET(fd, &rset);

    if (select(fd+1, &rset, NULL, NULL, NULL) == -1)
      continue;

    /* read size of waiting packet and expand buffer if necessary */
    if (ioctl(fd, SIOCINQ, &size) != -1 &&
	(size + sizeof(struct ip) + sizeof(struct udphdr)) > buf_size)
      {
	struct udp_dhcp_packet *newbuf = malloc(size + sizeof(struct ip) + sizeof(struct udphdr));
	if (!newbuf)
	  continue;
	else
	  {
	    buf_size = size + sizeof(struct ip) + sizeof(struct udphdr);
	    free(rawpacket);
	    rawpacket = newbuf;
	  }
      }
    
    msg.msg_control = control_u.control;
    msg.msg_controllen = sizeof(control_u);
    msg.msg_flags = 0;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    iov[0].iov_base = (char *)&rawpacket->data;
    iov[0].iov_len = buf_size - (sizeof(struct ip) + sizeof(struct udphdr));
    
    sz = recvmsg(fd, &msg, 0);

    if (sz < (sizeof(*header) - sizeof(header->options)) || 
	msg.msg_controllen < sizeof(struct cmsghdr))
      continue;
    
    iface_index = 0;
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)
	iface_index = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_ifindex;
  
    if (!(ifr.ifr_ifindex = iface_index) || ioctl(fd, SIOCGIFNAME, &ifr) == -1)
      continue;
    	
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
      continue;
    else
      iface_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
    
    header = (struct dhcp_packet *)&rawpacket->data;
    
    /* last ditch loop squashing. */
    if ((header->hops++) > 20)
      continue;

    if (header->op == BOOTREQUEST)
      {
	/* message from client */
	struct namelist *tmp;
	struct interface *iface;

	/* packets from networks we are broadcasting _too_
	   are explicitly not allowed to be forwarded _from_ */
	for (tmp = servers; tmp; tmp = tmp->next)
	  if (tmp->addr.s_addr == 0 && strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0)
	    break;
	if (tmp)
	  continue;

	/* check if it came from an allowed interface */
	for (tmp = except; tmp; tmp = tmp->next)
	  if (strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0)
	    break;
	if (tmp)
	  continue;
	
	if (interfaces)
	  { 
	    for (tmp = interfaces; tmp; tmp = tmp->next)
	      if (strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0)
		break;
	    if (!tmp)
	      continue;
	  }
	
	/* already gatewayed ? */
	if (header->giaddr.s_addr)
	  {
	    /* if so check if by us, to stomp on loops. */
	    for (iface = ifaces; iface; iface = iface->next)
	      if (iface->addr.s_addr == header->giaddr.s_addr)
		break;
	    if (iface)
	      continue;
	  }
	else
	  {
	    /* plug in our address */
	    header->giaddr = iface_addr;
	  }

	/* send to all configured servers. */
	for (tmp = servers; tmp; tmp = tmp->next)
	  {
	    /* Do this each time round to pick up address changes. */
	    if (tmp->addr.s_addr == 0)
	      {
		strncpy(ifr.ifr_name, tmp->name, IF_NAMESIZE);
		if (ioctl(fd, SIOCGIFBRDADDR, &ifr) == -1)
		  continue;
		saddr.sin_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
	      }
	    else
	      saddr.sin_addr = tmp->addr;
	    
	    saddr.sin_port = htons(DHCP_SERVER_PORT);
	    sendto(fd, &rawpacket->data, sz, 0, (struct sockaddr *)&saddr, sizeof(saddr));
	  }

	/* build address->interface index table for returning answers */
	for (iface = ifaces; iface; iface = iface->next)
	  if (iface->addr.s_addr == iface_addr.s_addr)
	    {
	      iface->index = iface_index;
	      break;
	    }

	/* not there, add a new entry */
	if (!iface && (iface = malloc(sizeof(struct interface))))
	  {
	    iface->next = ifaces;
	    ifaces = iface;
	    iface->addr = iface_addr;
	    iface->index = iface_index;
	  }
      }
    else if (header->op == BOOTREPLY)
      { 
	/* packet from server send back to client */
	if (header->ciaddr.s_addr)
	  {
	    /* client has configured address, this is easy (might never happen) */
	    saddr.sin_addr = header->ciaddr;
	    saddr.sin_port = htons(DHCP_CLIENT_PORT);
	    sendto(fd, &rawpacket->data, sz, 0, (struct sockaddr *)&saddr, sizeof(saddr));
	  }
	else
	  {
	    /* client not configured and cannot reply to ARP. Have to send
	       directly to its MAC address or broadcast. */

	    struct sockaddr_ll dest;
	    struct interface *iface;
	    u32 i, sum;
	    
	    /* look up interface index in cache */
	    for (iface = ifaces; iface; iface = iface->next)
	      if (iface->addr.s_addr == header->giaddr.s_addr)
		break;
			    
	    if ((header->hlen > 8) || !iface)
	      continue;
	    
	    dest.sll_ifindex =  iface->index;
	    dest.sll_family = AF_PACKET;
	    dest.sll_halen =  header->hlen;
	    dest.sll_protocol = htons(ETHERTYPE_IP);
	     
	    if (ntohs(header->flags) & 0x8000)
	      {
		memset(dest.sll_addr, 255,  header->hlen);
		rawpacket->ip.ip_dst.s_addr = INADDR_BROADCAST;
	      }
	    else
	      {
		memcpy(dest.sll_addr, header->chaddr, header->hlen); 
		rawpacket->ip.ip_dst.s_addr = header->yiaddr.s_addr;
	      }
	    
	    rawpacket->ip.ip_p = IPPROTO_UDP;
	    rawpacket->ip.ip_src.s_addr = iface_addr.s_addr;
	    rawpacket->ip.ip_len = htons(sizeof(struct ip) + 
					 sizeof(struct udphdr) +
					 sz) ;
	    rawpacket->ip.ip_hl = sizeof(struct ip) / 4;
	    rawpacket->ip.ip_v = IPVERSION;
	    rawpacket->ip.ip_tos = 0;
	    rawpacket->ip.ip_id = htons(0);
	    rawpacket->ip.ip_off = htons(0x4000); /* don't fragment */
	    rawpacket->ip.ip_ttl = IPDEFTTL;
	    rawpacket->ip.ip_sum = 0;
	    
	    for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
	      sum += ((u16 *)&rawpacket->ip)[i];
	    while (sum>>16)
	      sum = (sum & 0xffff) + (sum >> 16);  
	    rawpacket->ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
	    
	    rawpacket->udp.uh_sport = htons(DHCP_SERVER_PORT);
	    rawpacket->udp.uh_dport = htons(DHCP_CLIENT_PORT);
	    ((u8 *)&rawpacket->data)[sz] = 0; /* for checksum, in case length is odd. */
	    
	    rawpacket->udp.uh_sum = 0;
	    rawpacket->udp.uh_ulen = sum = htons(sizeof(struct udphdr) + sz);
	    sum += htons(IPPROTO_UDP);
	    for (i = 0; i < 4; i++)
	      sum += ((u16 *)&rawpacket->ip.ip_src)[i];
	    for (i = 0; i < (sizeof(struct udphdr) + sz + 1) / 2; i++)
	      sum += ((u16 *)&rawpacket->udp)[i];

	    while (sum>>16)
	      sum = (sum & 0xffff) + (sum >> 16);
	    rawpacket->udp.uh_sum = (sum == 0xffff) ? sum : ~sum;

	    sendto(rawfd, rawpacket, ntohs(rawpacket->ip.ip_len), 
		   0, (struct sockaddr *)&dest, sizeof(dest));
	  }
      }
  }

}
	    
