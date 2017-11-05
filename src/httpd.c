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
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
/************* STRUCTS ***********/

// Struct for methods that are allowed
typedef enum {HEAD, POST, GET} Methods;
const char* methodNames[] = {"HEAD", "POST", "GET"};
#define KEEP_ALIVE_TIMEOUT 30
#define MSG_SIZE  4096

// Struct for client request
typedef struct Request {
    Methods method;
    GString *host;
    GString *path;
    GString *pathPage;
    GString *query;
    GString *messageBody;
    GTimer *timer;
    GString *gMessage;
    GString *response;
    GString *cookie;
    GString *authorization;
    struct sockaddr_in client;
    int version;
    int keepAlive;
    SSL *ssl;
    BIO *bio_ssl;
} Request;

/********* PUBLIC VARIABLES **********/
int requestOk;
FILE *logFile;
int nfds;
struct Request requestArray[200];

/************** Functions ***************/

// Initialize the client request
void initRequest(int nfds) {
    requestArray[nfds].host = g_string_new("");
    requestArray[nfds].path = g_string_new("");
    requestArray[nfds].pathPage = g_string_new("");
    requestArray[nfds].messageBody = g_string_new("");
    requestArray[nfds].query = g_string_new("");
    requestArray[nfds].keepAlive = TRUE;
    requestArray[nfds].version = TRUE;
    requestArray[nfds].authorization = g_string_new("");
    requestArray[nfds].response = g_string_new(""); 
    requestArray[nfds].gMessage = g_string_new("");
    requestArray[nfds].cookie = g_string_new("");
    requestOk = TRUE;
    requestArray[nfds].timer = g_timer_new();
}

// free the client requests
void freeRequest(int nfds) {
    if(requestArray[nfds].host)
        g_string_free(requestArray[nfds].host, TRUE);
    if(requestArray[nfds].path)
        g_string_free(requestArray[nfds].path, TRUE);
    if(requestArray[nfds].pathPage)
        g_string_free(requestArray[nfds].pathPage, TRUE);
    if(requestArray[nfds].messageBody)
        g_string_free(requestArray[nfds].messageBody, TRUE);
    if(requestArray[nfds].query)
        g_string_free(requestArray[nfds].query, TRUE);
    if(requestArray[nfds].timer)
        g_timer_destroy(requestArray[nfds].timer);
    if(requestArray[nfds].cookie)
        g_string_free(requestArray[nfds].cookie, TRUE);
    if(requestArray[nfds].authorization)
        g_string_free(requestArray[nfds].authorization, TRUE);
    if(requestArray[nfds].gMessage)
        g_string_free(requestArray[nfds].gMessage, TRUE);
    if(requestArray[nfds].response)
        g_string_free(requestArray[nfds].response, TRUE); 
}

void InitializeSSL() {
    SSL_load_error_strings(); 
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
}

void DestroySSL() {
    ERR_free_strings(); 
    EVP_cleanup(); 
}

void ShutdownSSL(SSL *ssl) {
    SSL_shutdown(ssl); 
    SSL_free(ssl); 
}

// Log the message
void logMessage(int responseCode, int nfds) {
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
                                        requestArray[nfds].host->str,
                                        methodNames[requestArray[nfds].method],
                                        requestArray[nfds].pathPage->str,
                                        responseCode);

    // Insert into the log file
    fwrite(logString->str, (size_t) sizeof(gchar), (size_t) logString->len, logFile);

    fclose(logFile);
    g_string_free(logString, TRUE);
}

// Create the HTML page
void createHTMLPage(GString *html, gchar *body, int nfds) {

    //Create the first part of the HTML string
    g_string_append(html, "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Test page.</title>\n</head>\n<body>\n");   

    // Make the path to render in the webpage
    g_string_append(html,  "http://");
    //g_string_append(html,  " ");
    g_string_append(html, requestArray[nfds].host->str);
    // If it is POST render the message 
    
    g_string_append_printf(html, "%s", requestArray[nfds].pathPage->str);

    g_string_append(html,  " ");
    g_string_append_printf(html, "%s", inet_ntoa(requestArray[nfds].client.sin_addr));
    g_string_append(html,  ":");
    g_string_append_printf(html, "%d", ntohs(requestArray[nfds].client.sin_port));

    // If it is POST, render t
    if(g_strcmp0(body, "") != 0) {
        g_string_append_printf(html, "\n%s", body);
    }

    // render the key and the value in the path
    if (g_strcmp0(requestArray[nfds].pathPage->str, "/test") == 0) {
        gchar **splits = g_strsplit(requestArray[nfds].query->str, "&", 0);
        for (int i = 0; splits[i]; i++) {
            g_string_append_printf(html, "\n<br>%s", splits[i]);
        }
        g_strfreev(splits); 
    }

    // Create the last part of the HTML
    g_string_append(html, "\n</body>\n</html>\r\n\r\n");
}

void createColorHTMLPage(GString *html, int nfds) {

    //Create the first part of the HTML string
    g_string_append(html, "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Test page.</title>\n</head>\n<body");

    if(g_strcmp0(requestArray[nfds].query->str, "") == 0) {
        fprintf(stdout, "Cookie:%s\n", requestArray[nfds].cookie->str);
        fflush(stdout);
        g_string_append_printf(html, " style=\"background-color:%s\"", (requestArray[nfds].cookie->str)+3);
    }
    else {
        // Add the color that was requested as inline HTML
        g_string_append_printf(html, " style=\"background-color:%s\"", (requestArray[nfds].query->str)+3);
    }

    g_string_append(html, ">\n</body>\n</html>\r\n\r\n");
}

// Send bad request with HTML
void sendNotImplemented(int nfds) {
    // Make the header with right version
    if(requestArray[nfds].version) {
        g_string_append(requestArray[nfds].response, "HTTP/1.1 501 Not Implemented  \r\n");
    }
    else {
        g_string_append_printf(requestArray[nfds].response, "HTTP/1.0 501 Not Implemented \r\n");
    }
    // create the date
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);
    g_string_append_printf(requestArray[nfds].response, "Date: %s\r\n", timeBuffer); 

    // Insert other information to the head
    g_string_append(requestArray[nfds].response, "Server: Emre Can\r\n");
    g_string_append_printf(requestArray[nfds].response, "Content-Length: %lu\r\n", requestArray[nfds].messageBody->len);
    g_string_append(requestArray[nfds].response, "Content-Type: text/html; charset=utf-8\r\n");
    g_string_append(requestArray[nfds].response, "Connection: Closed\r\n");
    g_string_append(requestArray[nfds].response, "\r\n");
}

void sendForbidden(int nfds) { 
    g_string_assign(requestArray[nfds].messageBody, "403 - Forbidden \n"); 
    // Make the header with right version
    if(requestArray[nfds].version) {
        g_string_append(requestArray[nfds].response, "HTTP/1.1 403 Forbidden\r\n");
    }
    else {
        g_string_append_printf(requestArray[nfds].response, "HTTP/1.0 403 Forbidden\r\n");
    } 
    // create the date
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);
    g_string_append_printf(requestArray[nfds].response, "Date: %s\r\n", timeBuffer);
    // Insert other information to the head
    g_string_append(requestArray[nfds].response, "Server: Emre Can\r\n");
    g_string_append_printf(requestArray[nfds].response, "Content-Length: %lu\r\n", requestArray[nfds].messageBody->len);
    g_string_append(requestArray[nfds].response, "Content-Type: text/html; charset=utf-8\r\n");

    // Check if the connection is keep-alive
    if (requestArray[nfds].keepAlive) {
        g_timer_start(requestArray[nfds].timer);
        g_string_append(requestArray[nfds].response, "Connection: keep-alive\r\n");
    }
    else {
        g_string_append(requestArray[nfds].response, "Connection: closed\r\n");
    }

    //g_string_append_printf(requestArray[nfds].response, "WWW-Authenticate: Basic realm=\"login\"\r\n");
    g_string_append(requestArray[nfds].response, "\r\n");
    g_string_append(requestArray[nfds].response, requestArray[nfds].messageBody->str);
    g_string_append(requestArray[nfds].response, "\r\n\r\n"); 
}

void sendUnauthorized(int nfds) {
    g_string_assign(requestArray[nfds].messageBody, "401 - Unauthorized \n");
    // Make the header with right version
    if(requestArray[nfds].version) {
        g_string_append(requestArray[nfds].response, "HTTP/1.1 401 Unauthorized\r\n");
    }
    else {
        g_string_append_printf(requestArray[nfds].response, "HTTP/1.0 401 Unauthorized \r\n");
    }
    // create the date
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);
    g_string_append_printf(requestArray[nfds].response, "Date: %s\r\n", timeBuffer);
    // Insert other information to the head
    g_string_append(requestArray[nfds].response, "Server: Emre Can\r\n");
    g_string_append_printf(requestArray[nfds].response, "Content-Length: %lu\r\n", requestArray[nfds].messageBody->len);
    g_string_append(requestArray[nfds].response, "Content-Type: text/html; charset=utf-8\r\n");

    // Check if the connection is keep-alive
    if (requestArray[nfds].keepAlive) {
        g_timer_start(requestArray[nfds].timer);
        g_string_append(requestArray[nfds].response, "Connection: keep-alive\r\n");
    }
    else {
        g_string_append(requestArray[nfds].response, "Connection: closed\r\n");
    }

    g_string_append_printf(requestArray[nfds].response, "WWW-Authenticate: Basic realm=\"login\"\r\n");
    g_string_append(requestArray[nfds].response, "\r\n");
    g_string_append(requestArray[nfds].response, requestArray[nfds].messageBody->str);
    g_string_append(requestArray[nfds].response, "\r\n\r\n"); 
}

// Send OK requesst
void sendOKRequest(int nfds) {
    // Append to the response+
    if(requestArray[nfds].version) {
        g_string_append(requestArray[nfds].response, "HTTP/1.1 200 OK\r\n");
    }
    else {
        g_string_append(requestArray[nfds].response, "HTTP/1.0 200 OK\r\n");
    }

    // Get the HTML 
    GString *html = g_string_new("");
    
    // Check if client asked for color
    if(g_strcmp0(requestArray[nfds].pathPage->str, "/color") == 0) {
        createColorHTMLPage(html, nfds);
        if(g_strcmp0(requestArray[nfds].query->str, "")) {
            fprintf(stdout, "Im sending Set-cookie: \n");
            fflush(stdout);
            g_string_append_printf(requestArray[nfds].response, "Set-Cookie: %s\r\n", requestArray[nfds].query->str);        
        }
    }
    else {
        createHTMLPage(html, requestArray[nfds].messageBody->str, nfds);
    }
    // create the date
    time_t t = time(NULL);
    struct tm *currentTime = gmtime(&t);
    char timeBuffer[256];
    strftime(timeBuffer, sizeof timeBuffer, "%a, %d %b %Y %H:%M:%S %Z", currentTime);

    // Insert other information to the head
    g_string_append_printf(requestArray[nfds].response, "Date: %s\r\n", timeBuffer);
    g_string_append(requestArray[nfds].response, "Server: Emre Can \r\n");
    g_string_append(requestArray[nfds].response, "Last-Modified: Sat, 07 oct 2017 17:13:01 GMT \r\n");
    g_string_append(requestArray[nfds].response, "Accept-Ranges: bytes\r\n");
    g_string_append_printf(requestArray[nfds].response, "Content-Length: %lu\r\n", html->len);
    g_string_append(requestArray[nfds].response, "Content-Type: text/html; charset=utf-8\r\n");

    // Check if the connection is keep-alive
    if (requestArray[nfds].keepAlive) {
        g_timer_start(requestArray[nfds].timer);
        g_string_append(requestArray[nfds].response, "Connection: keep-alive\r\n");
    }
    else {
        g_string_append(requestArray[nfds].response, "Connection: closed\r\n");
    }
    g_string_append(requestArray[nfds].response, "\r\n");

    // Send the message body if its not HEAD request
    if (requestArray[nfds].method != HEAD) {
        g_string_append(requestArray[nfds].response, html->str );
    } 

    g_string_free(html, TRUE);
    // Print the message out
    fprintf(stdout, "Response: %s\n" , requestArray[nfds].response->str);
    fflush(stdout);
}

// Parsing the first line of the request
int ParsingFirstLine(int nfds) {
    // Get the first line of the message, split it to method
    // path and protocol/version
    gchar **firstLine = g_strsplit(requestArray[nfds].gMessage->str, " ", 3);

    // If the firs line is smaller than 3 close the connection
    if(g_strv_length(firstLine) < 3) {
        requestOk = FALSE;
    }

    // Parsing the method
    if (!(g_strcmp0(firstLine[0], "GET"))) {
        requestArray[nfds].method =  GET;
    }
    else if(!(g_strcmp0(firstLine[0], "POST"))) {
        requestArray[nfds].method = POST;
    }
    else if(!(g_strcmp0(firstLine[0], "HEAD"))) {
         requestArray[nfds].method = HEAD;
    }
    else {
        // close the connection
        requestOk = FALSE;
    }

fprintf(stdout, "firstline[0]: %s\n", firstLine[0]); 
fflush(stdout); 

    // paring the path
    g_string_assign(requestArray[nfds].path, firstLine[1]);

   // If the version is 1.0 not persistant connection
    if(g_str_has_prefix(firstLine[2], "HTTP/1.0")) {
        requestArray[nfds].keepAlive = FALSE;
        requestArray[nfds].version = FALSE;
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
int parseHeader(int nfds) {
    // Split the header on lines
    gchar **getHeader = g_strsplit(requestArray[nfds].gMessage->str, "\r\n\r\n", 2);
    gchar **splitHeaderLines = g_strsplit(getHeader[0], "\r\n", 0);

    // iterate through the header
    for(int i = 1; splitHeaderLines[i]; i++) {
        if (strlen(splitHeaderLines[i]) == 0) {
            continue;
        }

        // Split the lines and set to lowercase
        gchar **splitOnDelim = g_strsplit_set(splitHeaderLines[i], ": ", 2);
        gchar *toLowerDelim = g_ascii_strdown(splitOnDelim[0], -1);
         
        // Set the host
        if (!(g_strcmp0(toLowerDelim, "host"))) {
            g_string_assign(requestArray[nfds].host, g_strstrip(splitOnDelim[1]));
        }

        // Check if there is Keep-alive connection
        if (!(g_strcmp0(toLowerDelim, "connection"))) {
            if(!(g_strcmp0(splitOnDelim[1], "keep-alive"))) {
                requestArray[nfds].keepAlive = FALSE;
            }
        }

        if (!(g_strcmp0(toLowerDelim, "cookie"))) {
            g_string_assign(requestArray[nfds].cookie, g_strstrip(splitOnDelim[1]));
	}

        if (!(g_strcmp0(toLowerDelim, "authorization"))) {
            g_string_assign(requestArray[nfds].authorization, g_strstrip(splitOnDelim[1]));
        }

        g_strfreev(splitOnDelim);
        g_free(toLowerDelim);
    }

    // Check if there was a host
    if (requestArray[nfds].host == NULL) {
        printf("Host not found, close the connection\n");
        fflush(stdout);
        requestOk = FALSE;
    }

    // Free all variables
    g_strfreev(getHeader);
    g_strfreev(splitHeaderLines);

    return requestOk;
}

void validateAutherization(int nfds) {
    
}

// Create the request for the client
int createRequest(int nfds) {
    if(!(requestOk = ParsingFirstLine(nfds))) {
        requestOk = FALSE;
    }

    // Get the message body
    gchar *startOfBody = g_strrstr(requestArray[nfds].gMessage->str, (gchar*)"\r\n\r\n");
    gchar payload_buffer[requestArray[nfds].gMessage->len];

    // Parse the message body
    g_stpcpy(payload_buffer, startOfBody + 4 * sizeof(gchar));
    g_string_assign(requestArray[nfds].messageBody, payload_buffer);

    // split the path on question mark
    gchar **startOfQuery = g_strsplit(requestArray[nfds].path->str, "?", 2);

    // Parse the path without the query
    g_string_assign(requestArray[nfds].pathPage, startOfQuery[0]);

    // Check if there is query
    if(startOfQuery[1] != NULL) {
        // Parse the query
        g_string_assign(requestArray[nfds].query, startOfQuery[1]);
    }
    //parseURIParameters(nfds);
    g_strfreev(startOfQuery);

    // Check if the parseHeader returns true or false
    if(!(requestOk = parseHeader(nfds))) {
        requestOk =  FALSE;
    }

    // Check is requestOk is true or false, send the right
    // response to the client and write it to the logfile
    if(requestOk) {
        if(g_strcmp0(requestArray[nfds].pathPage->str, "/secret") == 0 || g_strcmp0(requestArray[nfds].pathPage->str, "/login") == 0) {
            // J Ú L Í Á .....................................................
            // CALLVALID AUTHENTICATION  
            // Send forbidden response 
            if(requestArray[nfds].ssl == NULL) {
                sendForbidden(nfds);          
                logMessage(403, nfds);
            }
        }
        else { 
            // Send ok response
            sendOKRequest(nfds);
            logMessage(200, nfds);
        }
    }
    else {
        // Send not implement response
        sendNotImplemented(nfds);
        logMessage(400, nfds);
    }

    return requestOk;
}

void createSalt(GString *salt) {
    struct timeval tv;
    static char result[64];

    gettimeofday(&tv, (struct timezone *) 0);
    strcat(result, l64a(tv.tv_usec));
    strcat(result, l64a(tv.tv_sec + getpid() + clock()));

    for (int i = 0; i < 64; i++)
    {
        result[i] = ((rand() % (0x7f - 0x34)) + 0x34);
    }

    result[63] = '\0';
    
    fprintf(stdout, "salt: %s\n", result);
    fflush(stdout);

    g_string_append(salt, result);
        
}

// Iitialize the database and create one user 
void initializeDatabase(){
    // create a key file containing a password
    GKeyFile *keyfile = g_key_file_new();
    GError* error = NULL;
    
    // Make a salt and hash it
    GString* salt = g_string_new("");
    createSalt(salt);
     
}

// Signaæl handler fo ctrl^c
void signalHandler(int signal) {
   // Check if it's SIGINT signal
    if (signal == SIGINT) {
        fprintf(stdout, "Caught SIGINT, shutting down all connections\n");
        fflush(stdout);

        // Close the connection
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    fprintf(stdout, "Connected to the Emre Can server\n");
    fflush(stdout);
   // GString *salt = g_string_new("");
   // createSalt(salt);    

    // Port number is missing, nothing to be done 
    if (argc != 3) {
        fprintf(stdout, "Wrong number of parameters, must be: %s, <port_number>. Exiting...\n", argv[0]);
        fflush(stdout);
        exit(-1);
    }
    
    // Signal handler for SIGINT
    if (signal(SIGINT, signalHandler) == SIG_ERR) {
        fprintf(stdout, "Cannot catch SIGINT\n");
        fflush(stdout);
    }

    int portHttp, portHttps, sockfdHttp, sockfdHttps, funcError, currSize, i, j, newfd = -1, receivedMsgSize;
    nfds = 2;
    struct sockaddr_in server;
    char message[MSG_SIZE];
    int pollTimeout = 1000;
    struct pollfd pollfds[200]; 
    int closeConn = FALSE;
    int shrinkArray = FALSE;
    socklen_t len;
    SSL_CTX *ctx; 
    //SSL *ssl; 

    // Get ports
    sscanf(argv[1], "%d", &portHttp);
    sscanf(argv[2], "%d", &portHttps);

    initializeDatabase();
    // Initialize the SSL functions, in order to be able to use SSL 
    InitializeSSL();
    ctx = SSL_CTX_new(SSLv23_method()); 

    // Create and bind a TCP socket.
    sockfdHttp = socket(AF_INET, SOCK_STREAM, 0);
    sockfdHttps = socket(AF_INET, SOCK_STREAM, 0);
    
    // Print error if socket failed
    if (sockfdHttp < 0 || sockfdHttps < 0) {
        fprintf(stdout, "Socket() failed\n");
        fflush(stdout);
        exit(-1);
    }

    // Network functions need arguments in network byte order instead of
    // host byte order. The macros htonl, htons convert the values.
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(portHttp);
    //server.sin_port = htons(portHttps);
    // Handle error if bind() fails
    if (bind(sockfdHttp, (struct sockaddr *) &server, (socklen_t) sizeof(server)) < 0) {
        fprintf(stdout, "bind() failed\n");
        fflush(stdout);
        exit(-1);
    }
 
    //funcError = listen(sockfdHttps, 32);

    server.sin_port = htons(portHttps);
    if (bind(sockfdHttps, (struct sockaddr *) &server, (socklen_t) sizeof(server)) < 0) {
        fprintf(stdout, "bind() failed\n");
        fflush(stdout);
        exit(-1);
    }

    // Before the server can accept messages, it has to listen to the
    // welcome port. A backlog of one connection is allowed.
    funcError = listen(sockfdHttp, 32);
    funcError = listen(sockfdHttps, 32);
    // Handle error if listen() fails
    if (funcError < 0) {
        fprintf(stdout, "listen() failed\n");
        fflush(stdout);
        exit(-1);
    }

    // Load the certificates and the private key 
    if (SSL_CTX_use_certificate_file(ctx, "fd.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stdout, "Certificate failure\nExiting ... ");
        exit(-1); 
    }  
    if (SSL_CTX_use_PrivateKey_file(ctx, "fd.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stdout, "Private key failure\nExiting ...");
        exit(-1); 
    } 
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stdout, "Not a match\nExiting  ..."); 
        exit(-1); 
    }   
    
    //ssl = SSL_new(ctx); 
    
    
    // Initialize the pollfd structure
    memset(pollfds, 0, sizeof(pollfds));
    pollfds[0].fd = sockfdHttp;
    pollfds[0].events = POLLIN;
    pollfds[1].fd = sockfdHttps;
    pollfds[1].events = POLLIN;

    for (;;) {
        funcError = poll(pollfds, nfds, pollTimeout); 
        // Check if poll failes
        if (funcError < 0) {
            fprintf(stdout, "poll() failed\n");
            fflush(stdout);
            break;
        } 
       
        currSize = nfds;
        for (i = 0; i < currSize; i++) {
            if ((pollfds[i].revents & POLLIN)) {
                // accept http connection from client
                if ((pollfds[i].fd == sockfdHttp)) {
                    // Accept new incoming connection if exists
                    // We first have to accept a TCP connection, newfd is a fresh
                    // handle dedicated to this connection. 
                    len = (socklen_t) sizeof(requestArray[nfds].client);
                    newfd = accept(sockfdHttp, (struct sockaddr *) &requestArray[nfds].client, &len);

                    // Add new connection to pollfd
                    pollfds[nfds].fd = newfd;
                    pollfds[nfds].events = POLLIN;
                    initRequest(nfds); 
                    nfds++;             
                  
                }
                // accept Https connection from client
                else if ((pollfds[i].fd == sockfdHttps)) {
                    // Accept new incoming connection if exists
                    // We first have to accept a TCP connection, newfd is a fresh
                    // handle dedicated to this connection.
                    len = (socklen_t) sizeof(requestArray[nfds].client);
                    // Accept connection from client 
                    newfd = accept(sockfdHttps, (struct sockaddr *) &requestArray[nfds].client, &len);

                    // Add new connection to pollfd
                    pollfds[nfds].fd = newfd;
                    pollfds[nfds].events = POLLIN;
                    // initialize the struct 
                    initRequest(nfds); 
                    // Set up SSL connection 
                    requestArray[nfds].ssl = SSL_new(ctx); 
                    SSL_set_fd(requestArray[nfds].ssl, newfd);
                    int SSLError = SSL_accept(requestArray[nfds].ssl); 
 
                    if (SSLError <= 0) {
                        fprintf(stdout, "Error: Was not accepted ");
                        fflush(stdout); 
                        ShutdownSSL(requestArray[nfds].ssl);
                        requestArray[nfds].ssl = NULL;
                        //closeConn = TRUE; 
                    }
                    else {
                        nfds++; 
                    }
                }
                // receve or read data from client
                else {  
                    memset(&message, 0, MSG_SIZE); 
                    // Check if it is SSL connection or over Http
                    if (requestArray[i].ssl != NULL) {
                        receivedMsgSize = SSL_read(requestArray[i].ssl, message, sizeof(message));
                    }
                    else {
                        receivedMsgSize = recv(pollfds[i].fd, message, sizeof(message), 0);
                    }

                    message[receivedMsgSize] = '\0';
                    // Check if client closed the connection
                    if (receivedMsgSize == 0) { 
                         closeConn = TRUE;
                         fprintf(stdout, "Client closed the connection\n");
                         fflush(stdout);
                         requestArray[i].keepAlive = FALSE;
                    }

                    fprintf(stdout, "received: \n %s \n", message); 
                    fflush(stdout);  

                    if(closeConn == FALSE) {  
                        initRequest(i);
                        g_string_append_len(requestArray[i].gMessage, message, receivedMsgSize);      
             
                        // Check if it is Http or Https, wite or send data
                        int createNoError = createRequest(i); 
                        if (requestArray[i].ssl != NULL) {
                            SSL_write(requestArray[i].ssl, requestArray[i].response->str, requestArray[i].response->len); 
                        }
                        else {
                            send(pollfds[i].fd, requestArray[i].response->str, requestArray[i].response->len, 0); 
                        }
                        
                        // If the method is unknown close the connection
                        if(!createNoError) {
                            closeConn = TRUE;
                            fprintf(stdout, "Bad request\n");
                            fflush(stdout);
                        }
                        // Not keep-alive connection, close the connection 
                        if (!requestArray[i].keepAlive) {
                            closeConn = TRUE;
                        } 
                    }
                }
            } 

            // Check if there is keep-alive timeout 
            if(requestArray[i].keepAlive) {
                gdouble timeLeft = g_timer_elapsed(requestArray[i].timer, NULL);
                if (timeLeft >= KEEP_ALIVE_TIMEOUT) {
                    closeConn = TRUE; 
                    requestArray[i].keepAlive = FALSE;
                }
            }

            if (closeConn) {
                // Clean up connections that were closed
                freeRequest(i);
                shutdown(pollfds[i].fd, SHUT_RDWR);
                close(pollfds[i].fd);
                pollfds[i].fd = -1;
                closeConn = FALSE;  
                shrinkArray = TRUE;
                fprintf(stdout, "Connection closed\n");
                fflush(stdout);
           }
        } 
        // After closing a connection shrink the poll and the request arryas
        if(shrinkArray) {
            for(i = 0; i <= nfds; i++)
            {
                if (pollfds[i].fd == -1)
                {
                    for (j = i; j < nfds; j++)
                    {
                        pollfds[j].fd = pollfds[j+1].fd;
                        memcpy(&requestArray[j], &requestArray[j+1], sizeof(requestArray[j+1])+1); 
                    }
                    nfds--;
                }
            }
        }
    }
}

