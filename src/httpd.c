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
#define KEEP_ALIVE_TIMEOUT 3
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
    GString* username; 
    GString* password;
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
    requestArray[nfds].username = g_string_new(""); 
    requestArray[nfds].password = g_string_new("");
}

void ShutdownSSL(SSL *ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// free the client requests
void freeRequest(int nfds) {
    if(requestArray[nfds].host->len > 0)
        g_string_free(requestArray[nfds].host, TRUE);
    if(requestArray[nfds].path->len > 0)
        g_string_free(requestArray[nfds].path, TRUE);
    if(requestArray[nfds].pathPage->len > 0)
        g_string_free(requestArray[nfds].pathPage, TRUE);
    if(requestArray[nfds].messageBody->len > 0)
        g_string_free(requestArray[nfds].messageBody, TRUE);
    if(requestArray[nfds].query->len > 0)
        g_string_free(requestArray[nfds].query, TRUE);
    if(requestArray[nfds].timer)
        g_timer_destroy(requestArray[nfds].timer);
    if(requestArray[nfds].cookie->len > 0)
        g_string_free(requestArray[nfds].cookie, TRUE);
    if(requestArray[nfds].authorization->len > 0)
        g_string_free(requestArray[nfds].authorization, TRUE);
    if(requestArray[nfds].gMessage->len > 0)
        g_string_free(requestArray[nfds].gMessage, TRUE);
    if(requestArray[nfds].response->len > 0)
        g_string_free(requestArray[nfds].response, TRUE); 
    if(requestArray[nfds].ssl != NULL)
        ShutdownSSL(requestArray[nfds].ssl); 
    if(requestArray[nfds].username->len > 0) 
        g_string_free(requestArray[nfds].username, TRUE); 
    if(requestArray[nfds].password->len > 0)
        g_string_free(requestArray[nfds].password, TRUE);
}

void InitializeSSL() {
    //SSL_load_error_strings(); 
    SSL_library_init(); 
    //OpenSSL_add_all_algorithms(); 
}

void DestroySSL() {
    ERR_free_strings(); 
    EVP_cleanup(); 
}


// Log the message
void logMessage(int responseCode, int nfds, int authenticated) {
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
    
    if (!requestArray[nfds].username) {
        g_string_printf(logString, "%s : %s %s\n%s : %d\n", timeBuffer,
                                        requestArray[nfds].host->str,
                                        methodNames[requestArray[nfds].method],
                                        requestArray[nfds].pathPage->str,
                                        responseCode);
    }
    else {
        if (authenticated) { 
            g_string_printf(logString, "%s : %s %s authenticated\n", timeBuffer,
                                        requestArray[nfds].host->str,
                                        requestArray[nfds].username->str
                                        );
        }
        else { 
            g_string_printf(logString, "%s : %s %s authentication error\n", timeBuffer,
                                        requestArray[nfds].host->str,
                                        requestArray[nfds].username->str
                                        );
 
        } 
    }

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

        // Check if client sent a cookie
        if (!(g_strcmp0(toLowerDelim, "cookie"))) {
            g_string_assign(requestArray[nfds].cookie, g_strstrip(splitOnDelim[1]));
    }

        // Check if client sent authorization
        if (!(g_strcmp0(toLowerDelim, "authorization"))) {
            g_string_assign(requestArray[nfds].authorization, g_strstrip(splitOnDelim[1]));
        }

        // Free variables that are not used anymore
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

GString *createHash(GString *salt, GString *password) {
    // add the password to the salt 
    g_string_append(salt, password->str);  
    // buffer to store the hashed password
    char hashedPassword[129];

    // hash the sting with SHA256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA512_CTX sha256;
    SHA512_Init(&sha256);
    SHA512_Update(&sha256, salt->str, salt->len);
    SHA512_Final(hash, &sha256);   

    // Hash the string multiple times
    int i = 0;                                                                                    
    for (i = 0; i < 10000; i++)
    {
        SHA512_CTX sha256;
        SHA512_Init(&sha256);
        SHA512_Update(&sha256, hashedPassword, SHA256_DIGEST_LENGTH * 2);
        SHA512_Final(hash, &sha256);
    }

    // set nullterminater at the end
    hashedPassword[128] = '\0';
    return g_string_new(hashedPassword);
}


void extractUserInformation(int nfds) {
    // Get the authorization from the client
    GString *authorizationHeader = requestArray[nfds].authorization; 
    gchar **splitAuth = g_strsplit(authorizationHeader->str, " ", 0);
   
    // if there is no autharization return
    if (g_strv_length(splitAuth) == 0) {
        g_string_free(authorizationHeader, TRUE);
        g_strfreev(splitAuth);
        return; 
    }

    //If credentials != Basic, then return 
    if (!g_strcmp0(splitAuth[1], "Basic") || g_strv_length(splitAuth) != 2) {
        g_strfreev(splitAuth); 
        g_string_free(authorizationHeader, TRUE); 
        return; 
    }

    // Decode the password
    gsize length; 
    guchar *credentials = g_base64_decode(splitAuth[1], &length); 

    //Done using splitAuth, free it
    g_strfreev(splitAuth); 


    //Get the username and password by splitting the credentials
    splitAuth = g_strsplit((char *) credentials, ":", 0); 

    // Add the password to the struct 
    g_string_append(requestArray[nfds].password, splitAuth[1]);
 
    //Add the username to the struct
    g_string_append(requestArray[nfds].username, splitAuth[0]); 
    g_strfreev(splitAuth); 
    g_string_free(authorizationHeader, TRUE); 

}

int validateAuthentication(int nfds) {
    // Get the hashed username and password
    extractUserInformation(nfds);

    // If there was no user information, return a 401 page to the client, since they cannot be authenticated
    if (!g_strcmp0(requestArray[nfds].username->str, "") || !g_strcmp0(requestArray[nfds].password->str, "")) {
        return FALSE;
    }

    // Opne the Keyfile to get username and password from user 
    GKeyFile *keyfile = g_key_file_new(); 
    GError* keyFileError = NULL; 
    if (!g_key_file_load_from_file(keyfile, "database.ini", G_KEY_FILE_NONE, &keyFileError)) {
        // An error occured, print the error and return
        fprintf(stdout, "An error occured in opening the keyfile: %s\n", keyFileError->message);
        g_key_file_free(keyfile);
        return FALSE; 
    }
    fprintf(stdout, "requestArray[nfds].username->str : %s\n", requestArray[nfds].username->str);
    fflush(stdout);
    // Get dat salt
    GString *salt = g_string_new("");
    gchar *pulledSalt =  g_key_file_get_string(keyfile, "salts", requestArray[nfds].username->str, NULL); 
    if (pulledSalt != NULL) {
        g_string_append(salt, g_key_file_get_string(keyfile, "salts", requestArray[nfds].username->str, NULL)); 
    }
  
    //If salt is missing, then you have to find some other way to get high
    if (salt->len == 0) {
        fprintf(stdout, "Error: Salt is missing. We're all very salty about that. Sorry.\n"); 
        fflush(stdout);  
        g_key_file_free(keyfile);
        g_string_free(salt, TRUE);
        return FALSE; 
    }


    GString *pulledPassword = g_string_new("");
    g_string_append(pulledPassword, g_key_file_get_value(keyfile, "passwords", requestArray[nfds].username->str, NULL));     
    //If there is no stored password, there is an error and the user cannot be authenticated
    if (pulledPassword->len == 0) {
        fprintf(stdout, "Error: Password is not in store. Cannot authenticate.\n"); 
        fflush(stdout); 
        g_key_file_free(keyfile);
        g_string_free(salt, TRUE); 
        g_string_free(pulledPassword, TRUE); 
        return FALSE; 
    }
    //g_string_append(storedPassword, pulledPassword->str); 
    GString *hashedPassword = createHash(salt, requestArray[nfds].password);  
      
    // Only authorize if the password in the database matches the password sent by the client
    if (!g_strcmp0(pulledPassword->str, hashedPassword->str)) {
        fprintf(stdout, "Error: Incorrect password. Cannot authenticate.\n"); 
        fflush(stdout); 
        g_key_file_free(keyfile);
        g_string_free(salt, TRUE); 
        g_string_free(pulledPassword, TRUE);
        g_string_free(hashedPassword, TRUE);  
        return FALSE; 
    }
    // Free variablea
    g_key_file_free(keyfile); 
    g_string_free(salt, TRUE); 
    g_string_free(pulledPassword, TRUE);
    g_string_free(hashedPassword, TRUE);  
     
    return TRUE;  
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
            // There is SSL present, but only allow access if authorization is validated           
            if (g_strcmp0(requestArray[nfds].authorization->str, "") != 0) {
                int authorized = validateAuthentication(nfds);
                if (!authorized) {
                    sendUnauthorized(nfds); 
                    logMessage(401, nfds, FALSE); 
                }
                else {
                    // Send ok response
                    sendOKRequest(nfds); 
                    logMessage(200, nfds, TRUE);  
                }
            }    
            else {
                // Send unauthorized response
                sendUnauthorized(nfds); 
                logMessage(401, nfds, FALSE);
            } 
        }  
        else { 
            // Send ok response
            sendOKRequest(nfds);
            logMessage(200, nfds, FALSE);
        }
    }
    else {
        // Send not implement response
        sendNotImplemented(nfds);
        logMessage(501, nfds, FALSE);
    }

    return requestOk;
}

// Create salt to hash with the password
void createSalt(GString *salt) {
    // Get time to set as seed
    struct timeval tv;
    static char result[64];
    gettimeofday(&tv, (struct timezone *) 0);
    strcat(result, l64a(tv.tv_usec));
    strcat(result, l64a(tv.tv_sec + getpid() + clock()));

    // Make random ascii value 
    for (int i = 0; i < 64; i++)
    {
        result[i] = ((rand() % (0x7f - 0x34)) + 0x34);
    }

    result[63] = '\0';

    g_string_append(salt, result);
        
}

// Iitialize the database and create one user 
void initializeDatabase(){
    // create a key file containing a password
    GKeyFile *keyfile = g_key_file_new();
    GError* error = NULL;
    
    // Make a salt and hash it
    GString *salt = g_string_new("");
    createSalt(salt);
    GString *password = g_string_new("password");
    GString *hashedPassword = g_string_new("");
    // Hash the salt and the password 
    hashedPassword = createHash(salt, password);
 
    // insert into the keyfile
    g_key_file_set_string(keyfile, "passwords", "admin", hashedPassword->str);
    g_key_file_set_string(keyfile, "salts", "admin", salt->str);
    g_key_file_set_string(keyfile, "passwords", "admin", hashedPassword->str);


   // insert into keyfile database
    int checkError = g_key_file_save_to_file(keyfile, "database.ini" , &error);  
    if(checkError < 0) {
        fprintf(stdout, "Error while adding admin to database\n");
        fflush(stdout);
        g_string_free(salt, TRUE);
        g_string_free(password, TRUE);
        g_string_free(hashedPassword, TRUE);
        g_key_file_free(keyfile);
        exit(1);
    }

    // free the salt and password after use
    g_string_free(salt, TRUE);
    g_string_free(password, TRUE);  
    g_string_free(hashedPassword, TRUE); 
    g_key_file_free(keyfile);
}

// Signal handler fo ctrl^c
void signalHandler(int signal) {
   // Check if it's SIGINT signal
    if (signal == SIGINT) {
        fprintf(stdout, "Caught SIGINT, shutting down all connections\n");
        fflush(stdout);
        // Close the connection
        exit(1);
        
        for(int i = 0; i < nfds; i++) {
            freeRequest(i);
        }
    }
}

int main(int argc, char *argv[])
{
    fprintf(stdout, "Connected to the Emre Can server\n");
    fflush(stdout);    

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

    // Get ports
    sscanf(argv[1], "%d", &portHttp);
    sscanf(argv[2], "%d", &portHttps);

    initializeDatabase();
    // Initialize the SSL functions, in order to be able to use SSL 
    InitializeSSL();
    SSL_CTX *ctx;
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
                    if(receivedMsgSize != 0) { 
                        
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
    SSL_CTX_free(ctx);
}


