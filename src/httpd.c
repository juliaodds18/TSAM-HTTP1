#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <poll.h>
#include <limits.h>
#include <errno.h>
#include <glib.h>
#include <glib/gprintf.h>

/********* PUBLIC VARIABLES **********/
struct pollfd pollfds[200];
int nfds; 

/************* STRUCTS ***********/

// Struct for methods that are allowed
typedef enum {HEAD, POST, GET} Methods;



// Struct for client request
typedef struct Request {
    Methods method;
    GString *host;
    GString *path;
    GString *pathPage;
    GString *messageBody;
} Request;

/************** Functions ***************/

// Initialize the client request
void initRequest(Request *request) {
    request->host = g_string_new("");
    request->path = g_string_new("");
    request->pathPage = g_string_new("");
    request->messageBody = g_string_new("");
}

void freeRequest(Request *request) {
    g_string_free(request->host, TRUE); 
    g_string_free(request->path, TRUE); 
    g_string_free(request->pathPage, TRUE);
    g_string_free(request->messageBody, TRUE);  
}

int createRequest(GString *gMessage) {
    Request request;
    initRequest(&request);
    int requestOk = TRUE;
    // Get the first line of the message, split it to method
    // path and protocol/version
    gchar **firstLine = g_strsplit(gMessage->str, " ", 3);
    
    // If the firs line is smaller than 3 close the connection
    if(g_strv_length(firstLine) < 3) {
	requestOk = FALSE;
    }
    
    // Parsing the method	
    if (!(g_strcmp0(firstLine[0], "GET"))) {
        request.method =  GET;
    }
    else if(!(g_strcmp0(firstLine[0], "POST"))) {
	request.method = POST;
    }
    else if(!(g_strcmp0(firstLine[0], "HEAD"))) {
        request.method = HEAD;
    }
    else {
	// close the connection 
	requestOk = FALSE;
    }

    // paring the path
    g_string_assign(request.path, firstLine[1]);

    // If the version is 1.0 not persistant connection
    //if(g_str_has_prefix(firstLine[2], "HTTP/1.0")) {
        // not KEEP A LIVE ALIVE LIE LIFE LIVE LIFED A LIVE FOR LIFE LIVE 
    //}
 
    g_strfreev(firstLine); 

    // Get the message body
    gchar *startOfBody = g_strrstr(gMessage->str, (gchar*)"\r\n\r\n");
    gchar payload_buffer[gMessage->len];
 
    if(startOfBody == NULL) {
	// What to do what to do ??? 
	// return FALSE;
    }
    
    // Parse the message body
    g_stpcpy(payload_buffer, startOfBody + 4 * sizeof(gchar));
    g_string_assign(request.messageBody, payload_buffer);

    gchar *startOfQuery = g_strrstr(request.path->str, (gchar*)"?"); 

    // Check if there is query 
    if(startOfQuery == NULL) {
	fprintf(stdout, "\n\nim in here \n\n");
	fflush(stdout);
	g_string_assign(request.pathPage, request.path->str);
    } 
    else {
       	fprintf(stdout, "\n\nim not suppose to be here \n\n");
        fflush(stdout);
    }
    return requestOk;
}

void signalHandler(int signal) {
    if (signal == SIGINT) {
	fprintf(stdout, "Caught SIGINT, shutting down all connections\n"); 
	fflush(stdout); 

	for (int i = 0; i < nfds; i++) {
	    close(pollfds[i].fd);
	}
    }
}



int main(int argc, char *argv[])
{  
    // Port number is missing, nothing to be done     
    if (argc != 2) {
	fprintf(stdout, "Wrong number of parameters, must be: %s, <port_number>. Exiting...\n", argv[0]);
	fflush(stdout);
	exit(-1);    
    } 

    if (signal(SIGINT, signalHandler) == SIG_ERR) {
	fprintf(stdout, "Cannot catch SIGINT\n"); 
	fflush(stdout); 
    }
 
    int port, sockfd = -1, funcError, on = 1, currSize, newfd = -1, i, j;
    struct sockaddr_in server;
    char buffer[1024];
    int timeout = 30*1000;
    int endServer = FALSE, shrinkArray = FALSE, closeConn = FALSE;
    nfds = 1;
    GString *gMessage = g_string_new("");


    sscanf(argv[1], "%d", &port); 

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    // Print error if socket failed
    if (sockfd < 0) {
	fprintf(stdout, "Socket() failed\n");
	fflush(stdout); 
	exit(-1); 
    }

    // Allow socket descriptor to be used more than once 
    // setsockopt sets options associated with a socket, can only be called for
    // sockets in the AF_INET domain. 
    // int setsockopt(int s, int level, int optname, char *optval, int optlen)
    // s = socket descriptor, level = level for which the option is being set
    // optname = name of a specified socket option (REUSEADDR), optval = 
    // pointer to option data, optlen = length of option data
    funcError = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
    // Handle error if setsockopt fails
    if (funcError < 0) {
	fprintf(stdout, "setsockopt() failed\n"); 
	fflush(stdout); 
	exit(-1); 
    } 

    // Network functions need arguments in network byte order instead of
    // host byte order. The macros htonl, htons convert the values.
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);
    funcError = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    // Handle error if bind() fails
    if (funcError < 0) {
	fprintf(stdout, "bind() failed\n"); 
	fflush(stdout); 
	exit(-1); 
    }
    // Before the server can accept messages, it has to listen to the
    // welcome port. A backlog of one connection is allowed.
    funcError = listen(sockfd, 1);
    // Handle error if listen() fails
    if (funcError < 0) {
	fprintf(stdout, "listen() failed\n"); 
	fflush(stdout); 
	exit(-1); 
    }

    // Initialize the pollfd structure 
    memset(pollfds, 0, sizeof(pollfds));
    pollfds[0].fd = sockfd; 
    pollfds[0].events = POLLIN; 
    // TImeout???
    fprintf(stdout, "sockfd: %d, pollfds[0]: %d\n", sockfd, pollfds[0].fd); 
    fflush(stdout); 



    while (endServer == FALSE) {
        fprintf(stdout, "before poll\n"); 
	fflush(stdout); 

	funcError = poll(pollfds, nfds, timeout);   
	
	if (funcError < 0) {
	    fprintf(stdout, "poll() failed\n"); 
	    fflush(stdout);
	    break;
	}
	if (funcError == 0) {
	    fprintf(stdout, "poll() timed out, exiting\n"); 
	    fflush(stdout); 
	    break; 
	}

	
	fprintf(stdout, "going into for loop in while, poll done\n");
	fflush(stdout); 
	currSize = nfds; 
	for (i = 0; i < currSize; i++) {
	     
	    
	    // Loop through file descriptors, determine whether it is
	    // the listening connection or an active connection 
	    if (pollfds[i].revents == 0) {
		fprintf(stdout, "this is a revent == 0\n"); 
		fflush(stdout);  
		continue; 
	    }

	    // revents needs to be POLLIN if not 0. Else, there is an error, end the server
	    if (pollfds[i].revents != POLLIN) {
		fprintf(stdout, "ERROR, REVENT NOT POLLIN\n");
		fflush(stdout); 
		endServer = TRUE;  
		break; 
	    } 

	    fprintf(stdout, "pollfds[i].fd: %d\n", pollfds[i].fd); 
	    if (pollfds[i].fd == sockfd) {
		// Listening descriptor is readable
	
		do {
		    fprintf(stdout, "trying to accept\n"); 
		    fflush(stdout); 
		    newfd = accept(sockfd, NULL, NULL);
		    fprintf(stdout, "after accept whoo \n"); 
		    fflush(stdout);  
		    if (newfd < 0) {
			if (errno != EWOULDBLOCK) { 
			    fprintf(stdout, "accept() failed\n"); 
			    fflush(stdout); 
			    endServer = TRUE;
			}
			break;
		    }

		    // Add new connection to pollfd
		    pollfds[nfds].fd = newfd; 
		    pollfds[nfds].events = POLLIN; 
		    nfds++;
		    fprintf(stdout, "Added new thing to thing\n"); 
		    
		    fflush(stdout); 

		} while (newfd != -1);	
	    }
	     else {

		
		// Existing connection is readable
		closeConn = FALSE; 
		fprintf(stdout, "hello from elseeee"); 
		fflush(stdout); 
		do {
		    
		    funcError = recv(pollfds[i].fd, buffer, sizeof(buffer) - 1, 0); 

		    if (funcError < 0) {
			if (errno != EWOULDBLOCK) {

			    fprintf(stdout, "recv() failed\n"); 
			    fflush(stdout); 
			    closeConn = TRUE; 
			}
			break; 
		    }

		    if (funcError == 0) {
			fprintf(stdout, "Connection closed by client\n"); 
			fflush(stdout); 
			break; 
		    }

		    // Parse the message into Gstring
		    int size = funcError; 
	            g_string_append_len(gMessage, buffer, size);	

		    // If the method is unknown close the connection
		    if(!createRequest(gMessage)) {
	    		// Close the connection.
	    		closeConn = TRUE; 
		    }

        	    buffer[size] = '\0';
        	    fprintf(stdout, "Received GString :\n%s\n", gMessage->str);
        	    fflush(stdout);	

		} while (TRUE); 

	    }
	    
	    
	    if (closeConn) {
		// Clean up connections that were closed
		close(pollfds[i].fd);
		pollfds[i].fd = -1; 
		shrinkArray = TRUE; 
	    }
	}


	if (shrinkArray) {

	    for (i = 0; i < nfds; i++) {
		if (pollfds[i].fd == -1) {
		    for (j = i; i < nfds; j++) 
			pollfds[j].fd = pollfds[j+1].fd; 
		    nfds--;
		}
	    }

	    shrinkArray = FALSE;
	}
       
    }
}
