//#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include "include/http_parser.h"

/* HTTP responses*/
#define RESPONSE_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed\r\n"

// To avoid file io, only return a simple HelloWorld!
#define RESPONSE_OK "HTTP/1.1 200 OK\r\n" \
                    "Content-Length: 21\r\n" \
                    "Content-Type: text/html\r\n" \
                    "Connection: keep-alive\r\n" \
                    "Server: uThreads-http\r\n" \
                    "\r\n" \
                    "<p>Hello World!</p>\n"
#define	HTTP_REQUEST_HEADER_END	"\n\r\n\r"

#define MAXIMUM_THREADS_PER_CLUSTER 8
#define INPUT_BUFFER_LENGTH         1024 //4 KB
#define PORT_NO                     8888
#define ERROR(msg) perror(msg);

http_parser_settings settings;
atomic_uint totalNumberofKTs = 0;

typedef struct Connection{
    /* used with polling */
    //PollData* pd;
    //related file descriptor
    int fd;
}Connection;
Connection* sconn; //Server socket

typedef struct {
    Connection* conn;
    bool keep_alive;
    char* url;
    int url_length;
} custom_data_t;

Connection* accept_conn(Connection *conn, struct sockaddr *addr, socklen_t *addrlen){
    //assert(conn->fd != -1);
    //check connection queue for waiting connections
    //Set the fd as nonblocking
    int sockfd = accept4(conn->fd, addr, addrlen, SOCK_NONBLOCK );
    while( (sockfd == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)){
        //User level blocking using nonblocking io
        //IOHandler::iohandler.wait(*pd, IOHandler::Flag::UT_IOREAD);
        sockfd = accept4(conn->fd, addr, addrlen, SOCK_NONBLOCK );
    }
    //otherwise return the result
    if(sockfd > 0){
        Connection *new_conn = (Connection *)malloc(sizeof(Connection));
        new_conn->fd = sockfd;
        return new_conn;
    }else{
        ERROR("Error on accpet");
        return NULL;
    }

}

void init_conn(Connection *conn){
    conn->fd = -1;
    //conn->pd = NULL;
}

void close_conn(Connection *conn){
    // IOHandler::iohandler.close(*pd)
    close(conn->fd);
}

ssize_t recv_conn(int fd, void *buf, size_t len, int flags){
    //assert(buf != NULL);
    //assert(fd != -1);

    ssize_t res = recv(fd, (void*)buf, len, flags);
    while( (res == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)){
           //User level blocking using nonblocking io
           //IOHandler::iohandler.wait(*pd, IOHandler::Flag::UT_IOREAD);
           res = recv(fd, buf, len, flags);
    }
    return res;
}

ssize_t send_conn(int fd, const void *buf, size_t len, int flags){
    //assert(buf != NULL);
    //assert(fd != -1);

    ssize_t res = send(fd, buf, len, flags);
    while( (res == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)){
        //IOHandler::iohandler.wait(*pd, IOHandler::Flag::UT_IOWRITE);
        res = send(fd, buf, len, flags);
    }
    return res;
}

ssize_t read_http_request(Connection *cconn, void *vptr, size_t n){

	size_t nleft;
	ssize_t nread;
	char * ptr;

	ptr = (char *)vptr;
	nleft = n;

	//uThread::yield(); //yield before read
    while(nleft >0){
    	if( (nread = recv_conn(cconn->fd, ptr, INPUT_BUFFER_LENGTH - 1, 0)) <0){
    		if (errno == EINTR)
    			nread =0;
    		else
    			return (-1);
    	}else if(nread ==0)
    		break;

    	nleft -= nread;

    	//Check whether we are at the end of the http_request
    	if(memcmp((const void*)&ptr[nread-4], HTTP_REQUEST_HEADER_END, 4))
    		break;

    	ptr += nread;

    }

    return (n-nleft);
}

ssize_t writen(Connection *cconn, const void *vptr, size_t n){

	size_t nleft;
	ssize_t nwritten;
	const char *ptr;

	ptr = (char*)vptr;
	nleft = n;

	while(nleft > 0){
		if( (nwritten = send_conn(cconn->fd, ptr, nleft, 0)) <= 0){
			if(errno == EINTR)
				nwritten = 0; /* If interrupted system call => call the write again */
			else
				return (-1);
		}
		nleft -= nwritten;
		ptr += nwritten;

	}

	return (n);
}
int on_headers_complete(http_parser* parser){

    //Check whether we should keep-alive or close
    custom_data_t *my_data = (custom_data_t*)parser->data;
    my_data->keep_alive = http_should_keep_alive(parser);

    return 0;
}
int on_header_field(http_parser* parser, const char* header, long unsigned int size){
    printf("%s\n", header);
    return 0;
}

/* handle connection after accept */
void *handle_connection(void *arg){

	Connection* cconn= (Connection*) arg;

	custom_data_t *my_data = (custom_data_t*)malloc(sizeof(custom_data_t));
	my_data->conn = cconn;
	my_data->keep_alive = 0;
	my_data->url = NULL;

    http_parser *parser = (http_parser *) malloc(sizeof(http_parser));
    if(parser == NULL)
        exit(1);
    http_parser_init(parser, HTTP_REQUEST);
	//pass connection and custom data to the parser
    parser->data = (void *) my_data;



    char buffer[INPUT_BUFFER_LENGTH]; //read buffer from the socket
    bzero(buffer, INPUT_BUFFER_LENGTH);

    size_t nparsed;
    ssize_t nrecvd; //return value for for the read() and write() calls.

    do{
        //Since we only accept GET, just try to read INPUT_BUFFER_LENGTH
        nrecvd = read_http_request(cconn, buffer, INPUT_BUFFER_LENGTH -1);
        if(nrecvd<0){
            //if RST packet by browser, just close the connection
            //no need to show an error.
            if(errno != ECONNRESET){
                ERROR("Error reading from socket");
                printf("fd %d\n", cconn->fd);
            }
            break;
        }

        nparsed = http_parser_execute(parser, &settings, buffer, nrecvd);
        if(nrecvd == 0) break;
        if(nparsed != nrecvd){
            ERROR("Error in Parsing the request!");
        }else{
            //We only handle GET Requests
            if(parser->method == 1)
            {
                //Write the response
                writen(cconn, RESPONSE_OK, sizeof(RESPONSE_OK));
            }else{
                //Method is not allowed
                writen(cconn, RESPONSE_METHOD_NOT_ALLOWED, sizeof(RESPONSE_METHOD_NOT_ALLOWED));
            }
        }
        //reset data
        my_data->url_length =0;
    }while(my_data->keep_alive);

    close_conn(cconn);
    free(my_data);
    free(cconn);
    free(parser);
}

int main(int argc, char *argv[]){
    struct sockaddr_in serv_addr;
    sconn = (Connection *)malloc(sizeof(Connection));
    sconn->fd = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);    //opening a socket for the tcp server
    if (sconn->fd < 0){
       ERROR("Error opening socket");
       exit(1);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));  //Init server_addr
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT_NO);

    if (bind(sconn->fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){  //bind socket 於本機所有IP(INADDR_ANY)和指定port
        ERROR("Error on binding");
        exit(1);
    }
    //listen for client, max queue length
    listen(sconn->fd, 65535);
    while(1){
        Connection *cconn = accept_conn(sconn, (struct sockaddr *)NULL, NULL);
        // uthreads -> handle connection
        handle_connection((void*) cconn);
    }
    close(sconn->fd);
    return 0;
}
