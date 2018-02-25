/* Copyright 2017 Georgios Migdos
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>           
#include <errno.h>
#include <stdio.h>            
#include <stdint.h>           
#include <string.h>           
#include <unistd.h>
#include <signal.h>           /* to register the SIGINT handler */
#include <sys/socket.h>       
#include <sys/ioctl.h>        
#include <arpa/inet.h>        
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include "sqlite3.h"

#define DB_FILE_NAME "srarpd.db"

#define SQL_QUERY_LOOKUP_IP_ADDRESS "SELECT * FROM ADDRESSES WHERE MAC_ADDRESS='%02x:%02x:%02x:%02x:%02x:%02x' ORDER BY IPV4_ADDRESS ASC LIMIT 1"
#define SQL_QUERY_LEN 96

#define RARP_OPCODE_REQUEST_REVERSE 0x0003
#define RARP_OPCODE_REPLY_REVERSE 0x0004

#define RX_BUFFER_LEN 65535
#define IPV4_ALEN 4
#define RARP_RESPONSE_PACKET_ETH_IPV4_LENGTH 42


#define ERR_CODE_NO_ERROR 0
#define ERR_CODE_COULD_NOT_CREATE_SOCKET -1
#define ERR_CODE_COULD_NOT_GET_MAC_AND_IP_ADDRESS -2
#define ERR_COULD_NOT_OPEN_DB -3

static volatile int continue_execution = 1; /* set to 0 by the SIGINT handler */

/**
 * RARP packet header
 */
typedef struct rarp_header_t {
  /** hardware address space */
  uint16_t hrd;
  /** protocol address space */
  uint16_t pro;
  /** hardware address length */
  uint8_t hln;
  /** protocol address length */
  uint8_t pln;
  /** opcode */
  uint16_t op;
} rarp_header_t;

/**
 * RARP packet data (assuming mapping Ethernet to IPv4 addresses)
 */
typedef struct rarp_data_t {
  /** source hardware address */
  uint8_t sha[ETH_ALEN];
  /** source protocol address */
  uint8_t spa[IPV4_ALEN];
  /** target hardware address */
  uint8_t tha[ETH_ALEN];
  /** target protocol address */
  uint8_t tpa[IPV4_ALEN];
} rarp_data_t;

typedef enum operation_mode_t {DB_UPSERT, DB_DELETE, DB_READ, DB_CLEAR, SERVE} operation_mode_t;

typedef struct args_t {
  operation_mode_t mode;
  char* interface; /* name of the network interface to use */
  char* db_update_data; /* a string containing the data for read/upsert/delete queries */
} args_t;

void error(char* msg){
  fprintf(stderr, "%s\n", msg);
}

void interrupt_handler(int not_used) {
  continue_execution = 0;
}

int get_mac_ip_address_and_index(char* interface_name, unsigned char *mac_addr, struct in_addr *ip_addr, int *index){
  int result = 0;
  struct ifreq ifr;
  int socket_descriptor = -1;
  
  if ((socket_descriptor = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0){
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface_name);
    if (ioctl (socket_descriptor, SIOCGIFHWADDR, &ifr) >= 0) {
      memcpy (mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN * sizeof (unsigned char));
      if (ioctl (socket_descriptor, SIOCGIFADDR, &ifr) >= 0) {
        memcpy (ip_addr, &(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr), sizeof (struct in_addr));
        if (ioctl (socket_descriptor, SIOCGIFINDEX, &ifr) >= 0) {
          *index = ifr.ifr_ifindex;
        } else {
          result = -3;
        }
      } else {
        result = -2;
      }
    } else {
      result = -1;
    }
    close(socket_descriptor);
  } else {
    result = -3;
  }

  return result;
}

int send_response(unsigned char *own_mac_addr, unsigned char *dst_mac_addr, rarp_data_t *response_data, int socket_descriptor, int interface_index){
  struct sockaddr_ll saddr_ll;
  uint8_t* buf = malloc(RARP_RESPONSE_PACKET_ETH_IPV4_LENGTH);
  int offset = 0;
  int bytes_sent = 0;
  int result = 0;
  if(buf){
    
    memcpy(&buf[offset], own_mac_addr, ETH_ALEN * sizeof(unsigned char));
    offset += ETH_ALEN * sizeof(unsigned char);
    
    memcpy(&buf[offset], dst_mac_addr, ETH_ALEN * sizeof(unsigned char));
    offset += ETH_ALEN * sizeof(unsigned char);
    
    buf[offset]   = 0x80;
    buf[offset+1] = 0x35;

    buf[offset+2] = 0x00;
    buf[offset+3] = 0x01;

    buf[offset+4] = 0x08;
    buf[offset+5] = 0x00;
    
    offset += 6;

    buf[offset]   = 6;
    buf[offset+1] = 4;
    buf[offset+2] = 0x00;
    buf[offset+3] = 0x04;

    offset += 4;

    memcpy(&buf[offset], &(response_data->sha), ETH_ALEN);
    offset += ETH_ALEN;
    
    memcpy(&buf[offset], &(response_data->spa), IPV4_ALEN);
    offset += IPV4_ALEN;

    memcpy(&buf[offset], &(response_data->tha), ETH_ALEN);
    offset += ETH_ALEN;
    
    memcpy(&buf[offset], &(response_data->tpa), IPV4_ALEN);
    offset += IPV4_ALEN;

    saddr_ll.sll_family = AF_PACKET;
    saddr_ll.sll_ifindex = interface_index;
    saddr_ll.sll_halen = ETH_ALEN;
    memcpy(saddr_ll.sll_addr, dst_mac_addr, ETH_ALEN);

    bytes_sent = sendto(socket_descriptor, buf, RARP_RESPONSE_PACKET_ETH_IPV4_LENGTH, 0, (const struct sockaddr*) &saddr_ll, sizeof(struct sockaddr_ll));
    if(bytes_sent < 0){
      error("RARP response transmission failed!");
      printf("error: %d, errno: %d\n", bytes_sent, errno);
      result = -2;
    }

    free(buf);

  } else {
    error("Could not allocate buffer for transmission.");
    result = -1;
  }
  return result;
}

static int sqlite_query_callback(void *output, int argc, char **argv, char **column_names){
  struct in_addr ip_addr;
  uint32_t *ipv4_addr = NULL;
  if(argc == 2){
    if(inet_aton(argv[1], &ip_addr)!=0){
      ipv4_addr = (uint32_t *)output;
      *ipv4_addr = ip_addr.s_addr;
    }
  }
  return 0;
}

int serve(char *interface_name){

  const size_t rarp_packet_size_c = sizeof(struct ethhdr) + sizeof(rarp_data_t);

  int result = ERR_CODE_NO_ERROR;
  int rx_sock = -1;
  int tx_sock = -1;
  unsigned char *buffer = (unsigned char*) malloc(RX_BUFFER_LEN * sizeof(unsigned char));
  struct sockaddr saddr;
  size_t saddr_len = sizeof (saddr);
  ssize_t bytes_read = 0;
  struct ethhdr *eth = NULL;
  rarp_header_t *rarp_header = NULL;
  rarp_data_t *rarp_data = NULL;
  unsigned char own_mac_address[ETH_ALEN] = {0};
  unsigned char dst_mac_address[ETH_ALEN] = {0};
  struct in_addr own_ip_address = {0};
  int interface_index = -1;
  uint32_t target_ipv4_addr = 0;
  struct timeval timeout;  
  sqlite3 *db = NULL;
  int sqlite_ret_code = 0;
  char *sqlite_error_msg = NULL;
  char sql_query[SQL_QUERY_LEN];
 
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  signal(SIGINT, interrupt_handler);

  sqlite_ret_code = sqlite3_open(DB_FILE_NAME, &db);

  if(sqlite_ret_code == 0){
    /* Create a RAW socket for reception: */
    rx_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  
    /* Create a RAW socket for transmission: */
  
    if(rx_sock >= 0){
  
      setsockopt (rx_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
  
      tx_sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
      
      if (tx_sock >= 0){
  
        if (get_mac_ip_address_and_index(interface_name, own_mac_address, &own_ip_address, &interface_index) >= 0){
          printf("Using interface '%s'\n", interface_name);
          printf("\tMAC address for %s: %02x:%02x:%02x:%02x:%02x:%02x\n", interface_name, own_mac_address[0], own_mac_address[1], own_mac_address[2], own_mac_address[3], own_mac_address[4], own_mac_address[5] );
          printf("\tIP address for %s : %d.%d.%d.%d\n", interface_name, ((uint8_t*)(&own_ip_address.s_addr))[0], ((uint8_t*)(&own_ip_address.s_addr))[1], ((uint8_t*)(&own_ip_address.s_addr))[2], ((uint8_t*)(&own_ip_address.s_addr))[3]);
  
          while(continue_execution){
            
            memset(buffer, 0, RX_BUFFER_LEN);
    
            bytes_read = recvfrom(rx_sock, buffer, RX_BUFFER_LEN, 0, &saddr, (socklen_t *) &saddr_len);
            
            if(bytes_read >= rarp_packet_size_c) {
              eth = (struct ethhdr *)(buffer);
              if(ntohs(eth->h_proto) == ETH_P_RARP){
    
                /* we have a RARP packet */
                rarp_header = (rarp_header_t *)(&buffer[sizeof(struct ethhdr)]);
                if(ntohs(rarp_header->op) == RARP_OPCODE_REQUEST_REVERSE){
                  if( (ntohs(rarp_header->hrd) == ETH_P_802_3) 
                      &&
                      (ntohs(rarp_header->pro) == ETH_P_IP)
                      &&
                      (rarp_header->hln == ETH_ALEN)
                      &&
                      (rarp_header->pln == IPV4_ALEN)
                    ){
                    /* it is a RARP request for an IPv4 address corresponding to 
                       a 802.3 MAC address -
                       let's lookup the address in the db and respond: */
  
                    rarp_header->op = htons(RARP_OPCODE_REPLY_REVERSE);
                    rarp_data = (rarp_data_t *)(&buffer[sizeof(struct ethhdr) + sizeof(rarp_header_t)]);
  
                    printf("Got RARP request for MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", rarp_data->sha[0], rarp_data->sha[1], rarp_data->sha[2], rarp_data->sha[3], rarp_data->sha[4], rarp_data->sha[5]);

                    memcpy(dst_mac_address, eth->h_source, ETH_ALEN * sizeof(unsigned char));

                    target_ipv4_addr = 0;
                    
                    snprintf(sql_query, SQL_QUERY_LEN, SQL_QUERY_LOOKUP_IP_ADDRESS, rarp_data->sha[0], rarp_data->sha[1], rarp_data->sha[2], rarp_data->sha[3], rarp_data->sha[4], rarp_data->sha[5]);
                    
                    sqlite_ret_code = sqlite3_exec(db, sql_query, sqlite_query_callback, &target_ipv4_addr, &sqlite_error_msg);
                    
                    if( sqlite_ret_code != SQLITE_OK ){
                      error(sqlite_error_msg);
                      sqlite3_free(sqlite_error_msg);
                    } else {

                      if (target_ipv4_addr != 0){

                        // printf("IPv4 address: %d.%d.%d.%d\n",  ((uint8_t*)(&target_ipv4_addr))[0], ((uint8_t*)(&target_ipv4_addr))[1], ((uint8_t*)(&target_ipv4_addr))[2], ((uint8_t*)(&target_ipv4_addr))[3]);

                        target_ipv4_addr = htonl(target_ipv4_addr);
                        memcpy(rarp_data->sha, own_mac_address, ETH_ALEN);
                        memcpy(rarp_data->spa, &own_ip_address.s_addr, IPV4_ALEN);
                        memcpy(rarp_data->tpa, &target_ipv4_addr, IPV4_ALEN);
      
                        send_response(own_mac_address, dst_mac_address, rarp_data, tx_sock, interface_index);

                      } else {
                        printf("Could not find a matching IPv4 address for MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", rarp_data->sha[0], rarp_data->sha[1], rarp_data->sha[2], rarp_data->sha[3], rarp_data->sha[4], rarp_data->sha[5]);
                      }

                    }
  
                  }
                  
                }
    
              }
            }
    
          }
        } else {
          error ("Failed to get MAC address for the local interface!");
          result = ERR_CODE_COULD_NOT_GET_MAC_AND_IP_ADDRESS;
        }
      
        close(tx_sock);
  
      } else {
        error("Could not create tx socket!");
        result = ERR_CODE_COULD_NOT_CREATE_SOCKET;
      }
  
      close(rx_sock);
      
    } else {
      error("Could not create rx socket!");
      result = ERR_CODE_COULD_NOT_CREATE_SOCKET;
    }

  } else {
    error("Could not open the database!");
    result = ERR_COULD_NOT_OPEN_DB;
  }

  free(buffer);

  sqlite3_close(db);

  return result;

}

int main(int argc, char** argv){
  if(argc > 1){
    return serve(argv[1]);
  }
  

}

