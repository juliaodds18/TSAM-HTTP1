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
#include <time.h>

/************* STRUCTS ***********/

// Struct for methods that are allowed
typedef enum {HEAD, POST, GET} Methods;
const char* methodNames[] = {"HEAD", "POST", "GET"};

// Struct for client request
typedef struct Request {
    Methods method;
    GString *host;
    GString *path;
    GString *pathPage;
    GString *query;
    GString *messageBody;
    int version;
    int keepAlive;
} Request;

/********* PUBLIC VARIABLES **********/
struct pollfd pollfds[200];
int nfds;
GString *gMessage;
FILE *logFile;
Request request;
GString *response;
int requestOk;
int sockfd;

/************** Functions ***************/

// Initialize the client request
void initRequest() {
    request.host = g_string_new("");
    request.path = g_string_new("");
    request.pathPage = g_string_new("");
    request.messageBody = g_string_new("");
    request.query = g_string_new("");
    request.keepAlive = TRUE;
    request.version = TRUE;
    response = g_string_sized_new(1024);
    requestOk = TRUE;
    sockfd = -1;
}

// free the client requests
void freeRequest() {
    g_string_free(request.host, TRUE); 
    g_string_free(request.path, TRUE); 
    g_string_free(request.pathPage, TRUE);
    g_string_free(request.messageBody, TRUE);  
    g_string_free(request.query, TRUE);
    g_string_free(response, TRUE);
}

// Close the connection
void closeConnection() {
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    freeRequest();
    exit(1);
}

// Log the message 
void logMessage(int responseCode) {
    // Create log file 
    logFile = fopen("logfile.log", "a"); 
    if (logFile == NULL) {
	fprintf(stdout, "Opening logfile failed"); 
	fflush(stdout); 
	exit(-1); 
    }
    
    // Create string that contains current time
    char timeBuffer[256];
    time_t t = time(NULL); 
    struct tm *currentTime = localtime(&t); 
    strftime(timeBuffer, 256, "%Y-%m-%dT%H:%M:%SZ", currentTime);  

    // Make the string to send into the log file
    GString *logString = g_string_new(NULL); 
    g_string_printf(logString, "%s : %s %s\n%s : %d\n", timeBuffer, 
					request.host->str, 
					methodNames[request.method],
					request.pathPage->str,
					responseCode ); 

    // Insert into the log file 
    fwrite(logString->str, (size_t) sizeof(gchar), (size_t) logString->len, logFile); 
 
    fclose(logFile); 
}

// Create the HTML page 
GString* createHTMLPage(gchar *body) {
   // Create the first part og the HTML string 
   GString *html = g_string_new("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Test page.</title>\n</head>\n<body>\n");

   // Check if it is POST or GET, insert the message body if it is POST
   // Else insert the path 
   if (g_strcmp0(body, "") != 0) { 
	g_string_append_printf(html, "%s\r", body); 

    }
    else {
        g_string_append(html,  "http:/");
        g_string_append_printf(html, "%s", request.pathPage->str);
        g_string_append(html,  " ");
        g_string_append_printf(html, "%s", request.host->str);
   }

   // Create the last part of the HTML
   g_string_append(html, "\n</body>\n</html>\r\n");
   return html;
}

// Send bad request with HTML
void sendBadRequest() {
    // Make the header with right version
    if(request.version) {
        g_string_append(response, "HTTP/1.1 400 Bad Request\r\n");
    }
    else {
        g_string_append(response, "HTTP/1.0 400 Bad Request\r\n");
    }
    // create the date 
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);
    g_string_append_printf(response, "Date: %s\r\n", timeBuffer);

    // Insert other information to the head
    g_string_append(response, "Server: Emre Can\r\n");
    g_string_append_printf(response, "Content-Length: %lu\r\n", request.messageBody->len);
    g_string_append(response, "Content-Type: text/html\r\n");
    g_string_append(response, "Connection: Closed\r\n");
    g_string_append(response, "\r\n");
    // create the HTML for bad request 
    GString * html = g_string_new("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>400</title>\n</head>\n<body>\n<h1>Bad Request</h1><p>Your browser sent a request that this server could not understand.</p><p>The request line contained invalid characters following the protocol string.</p>\n</body>\n</html>\n");
    g_string_append_printf(response, "%s\r\n", html->str);
}

// Send OK requesst 
void sendOKRequest() {
    // Append to the response
    if(request.version) {
        g_string_append(response, "HTTP/1.1 200 OK\r\n");
    }
    else {
	g_string_append(response, "HTTP/1.0 200 OK\r\n");
    }
    
    GString *html = g_string_new("");;

    if (request.method == POST) {
        html =  createHTMLPage(request.messageBody->str);
    }
    if (request.method == GET) {
        html = createHTMLPage("");
    }

    // create the date 
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);

    // INsert other information to the head 
    g_string_append_printf(response, "Date: %s\r\n", timeBuffer);
    g_string_append(response, "Server: Emre Can \r\n");
    g_string_append(response, "Last-Modified: Sat, 07 oct 2017 17:13:01 GMT \r\n");
    g_string_append(response, "Accept-Ranges: bytes\r\n");
    g_string_append_printf(response, "Content-Length: %lu\r\n", html->len);
    g_string_append(response, "Content-Type: text/html; charset=utf-8\r\n");

    
    // Check if the connection is keep-alive
    if(request.keepAlive) {
    	g_string_append(response, "Connection: Keep-Alive\r\n");
    }
    else {
	g_string_append(response, "Connection: Closed\r\n");
    } 

    g_string_append(response, "\r\n");

    // Send the message body if its not HEAD request
    g_string_append(response, html->str ); 	
 

fprintf(stdout, "Respone: afænæaslnsældGNlsæ\n");
    fflush(stdout);
    // Print the message out 
    fprintf(stdout, "Respone: %s\n" , response->str);
    fflush(stdout);
    g_string_append(response, "\r\n"); 
}

// Parsing the first line of the request 
int ParsingFirstLine() {
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
    if(g_str_has_prefix(firstLine[2], "HTTP/1.0")) {
        request.keepAlive = FALSE;
	request.version = FALSE;
    }

    // Check if the HTTP version is supprted
    if(!g_str_has_prefix(firstLine[2], "HTTP/1.0") && !g_str_has_prefix(firstLine[2], "HTTP/1.1")) {
        requestOk = FALSE;
    }
    
    // Free firstLine 
    g_strfreev(firstLine);

    return requestOk;
}

// Parse the all the header except the first line
int parseHeader() {
    // Split the header on lines
    gchar **getHeader = g_strsplit(gMessage->str, "\r\n\r\n", 2);
    gchar **splitHeaderLines = g_strsplit(getHeader[0], "\r\n", 0);

    // iterate through the header
    for(int i = 1; splitHeaderLines[i]; i++) {
        if (strlen(splitHeaderLines[i]) == 0) {
            continue;
        }

        // Split the lines and set to lowercase
        gchar **splitOnDelim = g_strsplit_set(splitHeaderLines[i], ":", 2);
        gchar *toLowerDelim = g_ascii_strdown(splitOnDelim[0], -1);

        // Set the host
        if (!(g_strcmp0(toLowerDelim, "host"))) {
            g_string_assign(request.host, splitOnDelim[1]);
        }

        // Check if there is Keep-alive connection
        if (!(g_strcmp0(toLowerDelim, "connection"))) {
            if(g_strcmp0(splitOnDelim[1], "keep-alive") || g_strcmp0(splitOnDelim[1], "close")) {
                request.keepAlive = FALSE;
            }
        }
        g_strfreev(splitOnDelim);
    }

    // Check if there was a host
    if (request.host == NULL) {
        printf("Host not found, close the connection\n");
	fflush(stdout);
        requestOk = FALSE;
    }

    // Free all variables
    g_strfreev(getHeader);
    g_strfreev(splitHeaderLines);

    return requestOk;
}

// Create the request for the client 
int createRequest(GString *gMessage) {
    initRequest(&request);
    
    if(!(requestOk = ParsingFirstLine(request))) {
	requestOk = FALSE;
    }  

    // Get the message body
    gchar *startOfBody = g_strrstr(gMessage->str, (gchar*)"\r\n\r\n");    
    gchar payload_buffer[gMessage->len];
    
    // Parse the message body
    g_stpcpy(payload_buffer, startOfBody + 4 * sizeof(gchar));
    g_string_assign(request.messageBody, payload_buffer);

    // split the path on question mark 
    gchar **startOfQuery = g_strsplit(request.path->str, "?", 2);

    // Parse the path without the query    
    g_string_assign(request.pathPage, startOfQuery[0]); 

    // Check if there is query 
    if(startOfQuery[1] != NULL) {
	// Parse the query
	g_string_assign(request.query, startOfQuery[1]);
    }

    g_strfreev(startOfQuery); 
 
    // Check if the parseHeader returns true or false
    if(!(requestOk = parseHeader(request))) {
	requestOk =  FALSE;
    }
  
    // Check is requestOk is true or false, send the right
    // response to the client and write it to the logfile 
    if(requestOk) {
        sendOKRequest(request); 
	logMessage(200);  
    }
    else {
	sendBadRequest();
	logMessage(400); 
    }
   
    return requestOk;
}

// Signaæ handler fo ctrl^c
void signalHandler(int signal) {
    // Check if it's SIGINT signal
    if (signal == SIGINT) {
	fprintf(stdout, "Caught SIGINT, shutting down all connections\n"); 
	fflush(stdout); 
	
	// Loop through sockets and close them 
	for (int i = 0; i < nfds; i++) {
	    close(pollfds[i].fd);
	}
	// Close the connection 
        closeConnection(); 
    }
}

int main(int argc, char *argv[])
{  
    fprintf(stdout, "Connected to the Emre Can server\n");
    fflush(stdout);
    // Port number is missing, nothing to be done     
    if (argc != 2) {
	fprintf(stdout, "Wrong number of parameters, must be: %s, <port_number>. Exiting...\n", argv[0]);
	fflush(stdout);
	exit(-1);    
    } 

    // Signal handler for SIGINT
    if (signal(SIGINT, signalHandler) == SIG_ERR) {
	fprintf(stdout, "Cannot catch SIGINT\n"); 
	fflush(stdout); 
    }
 
    // Variables 
    int port, funcError, on = 1, currSize, newfd = -1, i, j;
    struct sockaddr_in server;
    char buffer[1024];
    int timeout = 30*1000;
    int endServer = FALSE, shrinkArray = FALSE, closeConn = FALSE;
    nfds = 1;
    gMessage = g_string_new("");
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

    // Loop whilt endServer is FALSE
    while (endServer == FALSE) { 
	funcError = poll(pollfds, nfds, timeout);   
	
	// Check if poll failes 
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

	currSize = nfds; 
	// Loop through all file descriptors
	for (i = 0; i < currSize; i++) {
	     
	    
	    // Loop through file descriptors, determine whether it is
	    // the listening connection or an active connection 
	    if (pollfds[i].revents == 0) {
		continue; 
	    }

	    // revents needs to be POLLIN if not 0. Else, there is an error, end the server
	    if (pollfds[i].revents != POLLIN) {
		endServer = TRUE;  
		break; 
	    } 
 
	    if (pollfds[i].fd == sockfd) {
		// Listening descriptor is readable
	
		// Accept new incoming connection if exists
		do {
		    newfd = accept(sockfd, NULL, NULL);  
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

		} while (newfd != -1);	
	    }
	     else {

		timeout = time(NULL);
		// Existing connection is readable
		closeConn = FALSE;  

		// Receve data from connection 
		do {
		    memset(buffer, 0, 1024);		    
		    funcError = recv(pollfds[i].fd, buffer, sizeof(buffer) - 1, 0); 
		    
		    if (funcError < 0) {
			if (errno != EWOULDBLOCK) {

			    fprintf(stdout, "recv() failed\n"); 
			    fflush(stdout); 
			    closeConn = TRUE; 
			}
			break; 
		    }
			
		    buffer[funcError] = '\0';
			
		    // Check if buffer is empty
		    if (funcError == 0) {
			fprintf(stdout, "Connection closed by client\n"); 
			fflush(stdout);
			closeConn = TRUE; 
			break; 
		    }

		    // Parse the message into Gstring
		    int size = funcError; 
	            g_string_append_len(gMessage, buffer, size);	

		    // If the method is unknown close the connection
		    if(!createRequest(gMessage)) {
			// Send bad response and 
   	    		// Close the connection after sending respons
   	    		send(pollfds[i].fd, response->str, response->len, 0);
   			closeConn = TRUE; 
			closeConnection();
		    }
		    else {
			fprintf(stdout, "FYRIR SEND\n");
			fflush(stdout);
			// Send OK respons 
			send(pollfds[i].fd, response->str, response->len, 0);
			fprintf(stdout, "after SEND\n");
			fflush(stdout);
		    }

		} while (TRUE); 
	        
		if (closeConn) {
		    // Clean up connections that were closed
		    close(pollfds[i].fd);
		    pollfds[i].fd = -1; 
		    shrinkArray = TRUE; 
		}
	    }    
	} 

	// After connection is closed shrink array to  acceprt more connections
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
    closeConnection();
}
