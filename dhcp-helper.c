/* dhcp-helper is Copyright (c) 2004,2006 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: simon@thekelleys.org.uk */

#define VERSION "0.4"

#define COPYRIGHT "Copyright (C) 2004-2006 Simon Kelley" 

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
#include <netdb.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/capability.h>
/* There doesn't seem to be a universally-available 
   userpace header for this. */
extern int capset(cap_user_header_t header, cap_user_data_t data);
#include <sys/prctl.h>

#define PIDFILE "/var/run/dhcp-helper.pid"
#define USER "nobody"

#define DHCP_CHADDR_MAX  16
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

struct dhcp_packet_with_opts{
  struct dhcp_packet {
    unsigned char op, htype, hlen, hops;
    unsigned int xid;
    unsigned short secs, flags;
    struct in_addr ciaddr, yiaddr, siaddr, giaddr;
    unsigned char chaddr[DHCP_CHADDR_MAX], sname[64], file[128];
  } header;
  unsigned char options[312];
};


int main(int argc, char **argv)
{
  int fd = -1, netlinkfd, opt;
  struct ifreq ifr;
  struct sockaddr_in saddr;
  struct sockaddr_nl naddr;
  size_t buf_size = sizeof(struct dhcp_packet_with_opts);
  struct dhcp_packet *packet;
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

  if (!(packet = malloc(buf_size)))
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
  if (setsockopt(fd, SOL_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1 ||
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

  if ((netlinkfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    {
      perror("dhcp-helper: cannot create RTnetlink socket");
      exit(1);
    }
  
  naddr.nl_family = AF_NETLINK;
  naddr.nl_pad = 0;
  naddr.nl_pid = getpid();
  naddr.nl_groups = 0;
  if (bind(netlinkfd, (struct sockaddr *)&naddr, sizeof(struct sockaddr_nl)) == -1)
    {
      perror("dhcp-helper: cannot bind netlink socket");
      exit(1);
    }

  if (!debug)
    {
      FILE *pidfile;
      struct passwd *ent_pw = getpwnam(user);
      int i;
      gid_t dummy;
      struct group *gp;
      cap_user_header_t hdr = malloc(sizeof(*hdr));
      cap_user_data_t data = malloc(sizeof(*data)); 

      if (!hdr || !data)
	{
	  perror("dhcp-helper: cannot allocate memory");
	  exit(1);
	}

      hdr->version = _LINUX_CAPABILITY_VERSION;
      hdr->pid = 0; /* this process */
      data->effective = data->permitted = data->inheritable =
	(1 << CAP_NET_ADMIN) | (1 << CAP_SETGID) | (1 << CAP_SETUID);
                  
      /* Tell kernel to not clear capabilities when dropping root */
      if (capset(hdr, data) == -1 || prctl(PR_SET_KEEPCAPS, 1) == -1)
	{
	  perror("dhcp-helper: cannot set capabilities");
	  exit(1);
	}
      
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
	if (i != netlinkfd && i != fd)
	  close(i);

      setgroups(0, &dummy);

      if ((gp = getgrgid(ent_pw->pw_gid)))
	setgid(gp->gr_gid);
      setuid(ent_pw->pw_uid); 

      data->effective = data->permitted = 1 << CAP_NET_ADMIN;
      data->inheritable = 0;
      
      /* lose the setuid and setgid capbilities */
      capset(hdr, data);
    }
  
  while (1) {
    int iface_index;
    struct in_addr iface_addr;
    struct interface *iface;
    ssize_t sz;
    struct msghdr msg;
    struct iovec iov[1];
    struct cmsghdr *cmptr;
    struct in_pktinfo *pkt;
    union {
      struct cmsghdr align; /* this ensures alignment */
      char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
    } control_u;
        
    msg.msg_control = control_u.control;
    msg.msg_controllen = sizeof(control_u);
    msg.msg_flags = 0;
    msg.msg_name = &saddr;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    iov[0].iov_base = packet;
    iov[0].iov_len = buf_size;
    
    if ((sz = recvmsg(fd, &msg, MSG_PEEK)) != -1 && sz > (ssize_t)buf_size)
      {
	struct dhcp_packet *newbuf = malloc(sz);
	if (!newbuf)
	  continue;
	else
	  {
	    free(packet);
	    iov[0].iov_base = packet = newbuf;
	    iov[0].iov_len = buf_size = sz;
	  }
      }
    
    sz = recvmsg(fd, &msg, 0);
    
    if (sz < (ssize_t)(sizeof(struct dhcp_packet)) || 
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
    
    /* last ditch loop squashing. */
    if ((packet->hops++) > 20)
      continue;

    if (packet->hlen > DHCP_CHADDR_MAX)
      continue;

    if (packet->op == BOOTREQUEST)
      {
	/* message from client */
	struct namelist *tmp;
	
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
	if (packet->giaddr.s_addr)
	  {
	    /* if so check if by us, to stomp on loops. */
	    for (iface = ifaces; iface; iface = iface->next)
	      if (iface->addr.s_addr == packet->giaddr.s_addr)
		break;
	    if (iface)
	      continue;
	  }
	else
	  {
	    /* plug in our address */
	    packet->giaddr = iface_addr;
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
	    while(sendto(fd, packet, sz, 0, (struct sockaddr *)&saddr, sizeof(saddr)) == -1 &&
		  errno == EINTR);
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
    else if (packet->op == BOOTREPLY)
      { 
	/* packet from server send back to client */	
	saddr.sin_port = htons(DHCP_CLIENT_PORT);
	msg.msg_controllen = 0;
	msg.msg_namelen = sizeof(saddr);
	iov[0].iov_len = sz;
			   
	/* look up interface index in cache */
	for (iface = ifaces; iface; iface = iface->next)
	  if (iface->addr.s_addr == packet->giaddr.s_addr)
	    break;
	
	if (!iface)
	  continue;
            
	if (packet->ciaddr.s_addr)
	  saddr.sin_addr = packet->ciaddr;
	else if (ntohs(packet->flags) & 0x8000)
	  {
	    /* broadcast to 255.255.255.255 */
	    msg.msg_controllen = sizeof(control_u);
	    cmptr = CMSG_FIRSTHDR(&msg);
	    saddr.sin_addr.s_addr = INADDR_BROADCAST;
	    pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
	    pkt->ipi_ifindex = iface->index;
	    pkt->ipi_spec_dst.s_addr = 0;
	    msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	    cmptr->cmsg_level = SOL_IP;
	    cmptr->cmsg_type = IP_PKTINFO;
	  }
	else
	  {
	    /* client not configured and cannot reply to ARP. 
	       Insert arp entry direct.*/
	    struct {
	      struct nlmsghdr nlh;
	      struct ndmsg m;
	      struct rtattr addr_attr;
	      struct in_addr addr;
	      struct rtattr ll_attr;
	      char mac[DHCP_CHADDR_MAX];
	    } req;
	    
	    memset(&req, 0, sizeof(req));
	    memset(&naddr, 0, sizeof(naddr));
  
	    naddr.nl_family = AF_NETLINK;
	    
	    req.nlh.nlmsg_len = sizeof(req);
	    req.nlh.nlmsg_type = RTM_NEWNEIGH;
	    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE;
	    
	    req.m.ndm_family = AF_INET;
	    req.m.ndm_ifindex = iface->index;
	    req.m.ndm_state = NUD_REACHABLE;
	    
	    req.addr_attr.rta_type = NDA_DST;
	    req.addr_attr.rta_len = RTA_LENGTH(sizeof(struct in_addr));
	    req.addr = packet->yiaddr;
	    
	    req.ll_attr.rta_type = NDA_LLADDR;
	    req.ll_attr.rta_len = RTA_LENGTH(packet->hlen);
	    memcpy(req.mac, packet->chaddr, packet->hlen);

	    saddr.sin_addr = packet->yiaddr;
	    while (sendto(netlinkfd, &req, sizeof(req), 0, 
			  (struct sockaddr *)&naddr, sizeof(naddr)) == -1 &&
		   errno == EINTR);
	    
	  }

	while (sendmsg(fd, &msg, 0) == -1 && errno == EINTR);
      }
  }
}
    
	    
