#define _XOPEN_SOURCE 500 /* for pread */

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <math.h>
#include <fcntl.h>

#include "uhyve-het-migration-ondemand.h"

#define CHKPT_MDATA_FILE	"mdata.bin"
#define CHKPT_STACK_FILE	"stack.bin"
#define CHKPT_BSS_FILE		"bss.bin"
#define CHKPT_DATA_FILE		"data.bin"
#define CHKPT_HEAP_FILE		"heap.bin"
#define CHKPT_TLS_FILE		"tls.bin"
#define CHKPT_FDS_FILE		"fds.bin"


#define PORT		8080
#define PAGE_SIZE 	4096
#define NI_MAXHOST 	1025

extern int client_socket;
/*------------------------------ Server Side Code----------------------------*/

void print_server_ip ()
{
    	FILE *f;
    	char line[100] , *p , *c;

    	f = fopen("/proc/net/route" , "r");
	if(f == NULL)
	{
		perror("/proc/net/route file read failed");
        	exit(EXIT_FAILURE);
	}

    	while(fgets(line , 100 , f))
    	{
        	p = strtok(line , " \t");
        	c = strtok(NULL , " \t");

        	if(p!=NULL && c!=NULL)
        	{
            		if(strcmp(c , "00000000") == 0)
            		{
                		//printf("Default interface is : %s \n" , p);
                		break;
            		}
        	}
    	}

    	//which family do we require , AF_INET or AF_INET6
    	int fm = AF_INET;
    	struct ifaddrs *ifaddr, *ifa;
    	int family , s;
    	char host[NI_MAXHOST];

    	if (getifaddrs(&ifaddr) == -1)
    	{
        	perror("getifaddrs");
        	exit(EXIT_FAILURE);
    	}

    	//Walk through linked list, maintaining head pointer so we can free list later
    	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    	{
        	if (ifa->ifa_addr == NULL)
            		continue;

        	family = ifa->ifa_addr->sa_family;

        	if(strcmp( ifa->ifa_name , p) == 0)
        	{
            		if (family == fm)
            		{
                		s = getnameinfo( ifa->ifa_addr, (family == AF_INET) ? 
					sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), 
						host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

                		if (s != 0)
                		{
                    			printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    			exit(EXIT_FAILURE);
                		}

                		printf("Server Running at Address: %s", host);
            		}
            		printf("\n");
        	}
    	}

    freeifaddrs(ifaddr);
}

struct server_info* setup_page_response_server()
{
    	int opt = 1;
	int addrlen;
	struct sockaddr_in address;    

	struct server_info* server = (struct server_info*)malloc(sizeof(struct server_info));
	if(!server)
	{
		perror("Malloc Failed");
		exit(EXIT_FAILURE);
	}

	addrlen = sizeof(address);

    	// Creating socket file descriptor
    	if ((server->fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    	{
        	perror("Socket Failed");
        	exit(EXIT_FAILURE);
    	}

    	// Forcefully attaching socket to the port 8080
    	if (setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    	{
        	perror("Setsockopt Failed");
        	exit(EXIT_FAILURE);
    	}
    	address.sin_family = AF_INET;
    	address.sin_addr.s_addr = INADDR_ANY;
    	address.sin_port = htons( PORT );

    	// Forcefully attaching socket to the port 8080
    	if (bind(server->fd, (struct sockaddr *)&address,
                                 sizeof(address))<0)
    	{
        	perror("Bind Failed");
        	exit(EXIT_FAILURE);
    	}

	// Listen for connection request
    	if (listen(server->fd, 3) < 0)
       	{	
               	perror("Listen Failed");
               	exit(EXIT_FAILURE);
       	}

	// Accept connection request
       	if ((server->socket = accept(server->fd, (struct sockaddr *)&address,
                       	       (socklen_t*)&addrlen))<0)
       	{
               	perror("Accept Failed");
               	exit(EXIT_FAILURE);
       	}
	
        return server;
}

struct packet* receive_page_request(struct server_info *server)
{
    	char buffer[PAGE_SIZE] = {0};
	int valread;

	struct packet* recv_packet = (struct packet*)malloc(sizeof(struct packet));
	if(!recv_packet)
	{
		perror("Malloc Failed");
		exit(EXIT_FAILURE);
	}

	// Read received data
       	valread = read(server->socket , buffer, PAGE_SIZE);
	recv_packet = (struct packet*)buffer;

	return recv_packet;
}

int send_page_response(int sock, int fd, uint64_t offset)
{
	char buffer[PAGE_SIZE];

	if(pread(fd, buffer, PAGE_SIZE, offset) != PAGE_SIZE)
	{
		fprintf(stderr, "Cannot read file at offset 0x%x\n", offset);
		return -1;
	}

	send(sock, buffer, PAGE_SIZE, 0 );
	return 0;			
}

int on_demand_page_migration(uint64_t heap_size, uint64_t bss_size)
{
	const char* file_name;
	section type;
	struct packet *recv_packet = NULL;
	int heap_fd = -1, bss_fd = -1, fd;
	int ret;

	struct server_info *server = setup_page_response_server();
	print_server_ip();

	while(1)
	{
		recv_packet = receive_page_request(server);
		switch(recv_packet->type)
		{
			case BSS:
				if(bss_fd == -1)
				{
					bss_fd = open(CHKPT_BSS_FILE, O_RDONLY, 0);
					if(bss_fd == -1) 
					{
						perror("opening bss file");
						ret = -1;
						goto clean;
					}
				}
				fd = bss_fd;
				bss_size -= PAGE_SIZE;
				break;

			case HEAP:
				if(heap_fd == -1)
				{
					heap_fd = open(CHKPT_HEAP_FILE, O_RDONLY, 0);
					if(heap_fd == -1) 
					{
						perror("opening bss file");
						ret = -1;
						goto clean;
					}
				}
				fd = heap_fd;
				heap_size -= PAGE_SIZE;
				break;

			default:
				fprintf(stderr, "Unsupported Request Type. Closing server.\n");
				ret = -1;
				goto clean;
		}

		if(send_page_response(server->socket, fd, recv_packet->address) == -1)
		{
			fprintf(stderr, "Read error Closing the Server");
			ret = -1;
			goto clean;
		}

		//free(recv_packet);

		if(heap_size <= 0)// && bss_size <=0)
		{
			printf("Closing Server\n");
			goto clean;
		}
		else printf("heap size = %lu\n", heap_size);
	}

clean:
	if(bss_fd != -1)
		close(bss_fd);
	if(heap_fd != -1)
		close(heap_fd);
	close(server->fd);
	close(server->socket);
	free(server);

	return ret;
}

/*--------------------------------- Client Side Code ------------------------------------*/

int connect_to_page_response_server()
{
	struct sockaddr_in address;
    	int sock = 0, valread;
    	struct sockaddr_in serv_addr;
    	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    	{
        	perror("Socket creation error\n");
        	return -1;
    	}

    	memset(&serv_addr, '0', sizeof(serv_addr));

    	serv_addr.sin_family = AF_INET;
    	serv_addr.sin_port = htons(PORT);

    	// Convert IPv4 and IPv6 addresses from text to binary form
    	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
    	{
        	perror("Invalid address/ Address not supported\n");
		close(sock);
        	return -1;
    	}

    	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    	{
        	perror("Connection Failed\n");
		close(sock);
        	return -1;
    	}

	return sock;
}

int send_page_request(section type, uint64_t address, char *buffer)
{
	int valread;
	
	struct packet* send_packet = (struct packet*)malloc(sizeof(struct packet));
	send_packet->type = type;
	send_packet->address = address;

	send(client_socket , (const void*)send_packet , sizeof(struct packet) , 0 );
    	valread = read(client_socket ,buffer, PAGE_SIZE);
	
	free(send_packet);

	return 0;
}
