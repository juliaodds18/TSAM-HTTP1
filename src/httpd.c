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
#include <sys/ioctl.h>
#include <arpa/inet.h>

/************* STRUCTS ***********/

// Struct for methods that are allowed
typedef enum {HEAD, POST, GET} Methods;
const char* methodNames[] = {"HEAD", "POST", "GET"};
#define KEEP_ALIVE_TIMEOUT 30 

// Struct for client request
typedef struct Request {
    Methods method;
    GString *host;
    GString *path;
    GString *pathPage;
    GString *query;
    GString *messageBody;
    GTimer *timer;
    struct sockaddr_in client;
    int version;
    int keepAlive;
} Request;

/********* PUBLIC VARIABLES **********/
GString *gMessage;
Request request;
GString *response;
int requestOk;
FILE *logFile;

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
    request.timer = g_timer_new();
    //sockfd = -1;
}

// free the client requests
void freeRequest() {
    g_string_free(request.host, TRUE);
    g_string_free(request.path, TRUE);
    g_string_free(request.pathPage, TRUE);
    g_string_free(request.messageBody, TRUE);
    g_string_free(request.query, TRUE);
    g_string_free(response, TRUE);
    g_timer_destroy(request.timer);
}

// Close the connection
void closeConnection() {
    //shutdown(sockfd, SHUT_RDWR);
    //close(sockfd);
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

    // Make the path to render in the webpage
    g_string_append(html,  "http://");
    //g_string_append(html,  " ");
    g_string_append_printf(html, "%s", request.host->str);
    // If it is POST render the message 
    
    g_string_append_printf(html, "%s", request.pathPage->str);

    g_string_append(html,  " ");
    g_string_append_printf(html, "%s", inet_ntoa(request.client.sin_addr));
    g_string_append(html,  ":");
    g_string_append_printf(html, "%d", ntohs(request.client.sin_port));

    // If it is POST, render t
    if(g_strcmp0(body, "") != 0) {
        g_string_append_printf(html, "\n%s", body);
    }

    // Create the last part of the HTML
    g_string_append(html, "\n</body>\n</html>\r\n\r\n");
    return html;
}

// Send bad request with HTML
void sendBadRequest() {
    // Make the header with right version
    if(request.version) {
        g_string_append(response, "HTTP/1.1 501 Not Implemented\r\n");
    }
    else {
        g_string_append(response, "HTTP/1.0 501 Not Implemented\r\n");
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
    g_string_append(response, "Content-Type: text/html; charset=utf-8\r\n");
    g_string_append(response, "Connection: Closed\r\n");
    g_string_append(response, "\r\n");
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

    // Get the HTML 
    GString *html = g_string_new("");
    html =  createHTMLPage(request.messageBody->str);

    // create the date
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);

    // Insert other information to the head
    g_string_append_printf(response, "Date: %s\r\n", timeBuffer);
    g_string_append(response, "Server: Emre Can \r\n");
    g_string_append(response, "Last-Modified: Sat, 07 oct 2017 17:13:01 GMT \r\n");
    g_string_append(response, "Accept-Ranges: bytes\r\n");
    g_string_append_printf(response, "Content-Length: %lu\r\n", html->len);
    g_string_append(response, "Content-Type: text/html; charset=utf-8\r\n");

    // Check if the connection is keep-alive
    if (request.keepAlive) {
        g_timer_start(request.timer);
        g_string_append(response, "Connection: Keep-Alive\r\n");
    }
    else {
        g_string_append(response, "Connection: Closed\r\n");
    }
    g_string_append(response, "\r\n");

    // Send the message body if its not HEAD request
    if (request.method != HEAD) {
        g_string_append(response, html->str );
    } 

    html = g_string_new("");

    g_string_free(html, TRUE);
    // Print the message out
    fprintf(stdout, "Respone: %s\n" , response->str);
    fflush(stdout);;
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
        fprintf(stdout, "suppose ti be");
        fflush(stdout);
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
            if(!(g_strcmp0(splitOnDelim[1], "keep-alive"))) {
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

    if(!(requestOk = ParsingFirstLine())) {
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
    if(!(requestOk = parseHeader())) {
        requestOk =  FALSE;
    }

    // Check is requestOk is true or false, send the right
    // response to the client and write it to the logfile
    if(requestOk) {
        sendOKRequest();
        logMessage(200);
    }
    else {
        sendBadRequest();
        logMessage(400);
    }

    return requestOk;
}


// Signaæl handler fo ctrl^c
void signalHandler(int signal) {
   // Check if it's SIGINT signal
    if (signal == SIGINT) {
        fprintf(stdout, "Caught SIGINT, shutting down all connections\n");
        fflush(stdout);

        // Loop through sockets and close them
   /*     for (int i = 0; i < nfds; i++) {
            close(pollfds[i].fd);
        }*/
        // Close the connection
        closeConnection(request);
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

    int port, sockfd, funcError;
    struct sockaddr_in server;
    char message[1024];
    gMessage = g_string_new("");
    sscanf(argv[1], "%d", &port);

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // Print error if socket failed
    if (sockfd < 0) {
        fprintf(stdout, "Socket() failed\n");
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


    for (;;) {
        // We first have to accept a TCP connection, connfd is a fresh
        // handle dedicated to this connection.
        socklen_t len = (socklen_t) sizeof(request.client);
        int connfd = accept(sockfd, (struct sockaddr *) &request.client, &len);

        // Receive from connfd, not sockfd.
        ssize_t sizeMessage = recv(connfd, message, sizeof(message) - 1, 0);

        message[sizeMessage] = '\0';
        fprintf(stdout, "Received:\n%s\n", message);
        g_string_append_len(gMessage, message, sizeMessage);

        // If the method is unknown close the connection
        if(!createRequest(gMessage)) {
            // Send bad response and
            // Close the connection after sending respons
            send(connfd, response->str, response->len, 0);
            // closeConn = TRUE;
        }
        else {
            // Send OK respons
            send(connfd, response->str, response->len, 0);
        } 

        // Send the message back.
        //send(connfd, message, (size_t) n, 0);

        // Close the connection.
        if (!request.keepAlive) {
            gMessage = g_string_new("");
            shutdown(connfd, SHUT_RDWR);
            close(connfd);
        }

        // Keep-alive 
        gdouble timeLeft = g_timer_elapsed(request.timer, NULL);
        int keep = 1;
        while(keep == 1) {
            timeLeft = g_timer_elapsed(request.timer, NULL);
            if (timeLeft >= KEEP_ALIVE_TIMEOUT) {
                fprintf(stdout, "Timeout, closing the connection.\n");
                fflush(stdout);
                gMessage = g_string_new("");
                shutdown(connfd, SHUT_RDWR);
                close(connfd);
                keep = 0;
            }
        }
    }
}

