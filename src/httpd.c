#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <glib/gprintf.h>

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
