#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

/************* STRUCTS ***********/

// Struct for methods that are allowed
typedef enum {HEAD, POST, GET} Methods;



// Struct for client request
typedef struct Request {
    Methods method;
    GString *host;
    GString *path;
    GString *pathPage;
} Request;

/************** Functions ***************/

// Initialize the client request
void initRequest(Request *request) {
    request->host = g_string_new("");
    request->path = g_string_new("");
    request->pathPage = g_string_new("");
}

int createRequest(GString *gMessage) {
    Request request;
    initRequest(&request);

    // Set the method of request 	
    if ((g_str_has_prefix(gMessage->str, "GET"))) {
        request.method =  GET;
    }
    else if(g_str_has_prefix(gMessage->str, "POST")) {
	request.method = POST;
    }
    else if(g_str_has_prefix(gMessage->str, "HEAD")) {
        request.method = HEAD;
    }
    else {
	// close the connection 
	return FALSE;
    }
    return TRUE;
}


int main(int argc, char *argv[] )
{
    int sockfd;
    struct sockaddr_in server, client;
    char message[1024];
    int port; 
    GString *gMessage = g_string_new("");

    sscanf(argv[1], "%d", &port); 

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Network functions need arguments in network byte order instead of
    // host byte order. The macros htonl, htons convert the values.
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);
    bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    // Before the server can accept messages, it has to listen to the
    // welcome port. A backlog of one connection is allowed.
    listen(sockfd, 1);

    for (;;) {
        // We first have to accept a TCP connection, connfd is a fresh
        // handle dedicated to this connection.
        socklen_t len = (socklen_t) sizeof(client);
        int connfd = accept(sockfd, (struct sockaddr *) &client, &len);
 	
	// Empty the gstring before reuse
	g_string_truncate(gMessage, 0);

        // Receive from connfd, not sockfd.
        ssize_t n = recv(connfd, message, sizeof(message) - 1, 0);
	
	if (n < 0) {
            //if (errno != EWOULDBLOCK) {
	        fprintf(stdout, "recv() failed\n");
                fflush(stdout);
		// Have to close the connection 
            //}
         }

         if (n == 0) {
             fprintf(stdout, "Connection closed by client\n");
             fflush(stdout);
        }

        // Parse the message into Gstring
        g_string_append_len(gMessage, message, n);	

	// If the method is unknown close the connection
	if(!createRequest(gMessage)) {
	    // Close the connection.
	    shutdown(connfd, SHUT_RDWR);
	    close(connfd);
	}

        message[n] = '\0';
        fprintf(stdout, "Received GString :\n%s\n", gMessage->str);
        fflush(stdout);	
	
		

	// Convert message to upper case.
        for (int i = 0; i < n; ++i) message[i] = toupper(message[i]);

        // Send the message back.
        send(connfd, message, (size_t) n, 0);

        // Close the connection.
        shutdown(connfd, SHUT_RDWR);
        close(connfd);
    }

}
