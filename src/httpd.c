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
#include <glib.h>

int listen_port = 0;

/*struct GOptionEntry {
  const gchar *long_name;
  gchar        short_name;
  gint         flags;

  GOptionArg   arg;
  gpointer     arg_data;
  
  const gchar *description;
  const gchar *arg_description;
};*/
static GOptionEntry entries[] = {
  {"port", 'p', 0, G_OPTION_ARG_INT, &listen_port,
   "Port to bind to", NULL},
  {NULL}
};

int main(int argc, char *argv[])
{
    // nfds = number of instances in pollfds array, originally only one (sockfd)
    
    // A GOptionContext struct defines which options are accepted by the commandline option parser
    GOptionContext *context;
    GError *error = NULL;

    // Set the name of our HTTP server
    context = g_option_context_new ("Emru Can server");
    g_option_context_add_main_entries(context, entries, NULL);  

    // Check if the parsing was successful
    if (!g_option_context_parse(context, &argc, &argv, &error))
    {
      g_critical("Parsing failed: %s:%s\n", argv[0], error->message);
      exit(0);
    }


    int sockfd, funcError, on = 1, nfds = 1;
    struct sockaddr_in server, client;
    char message[512];
    struct pollfd pollfds[200];
    int timeout = INT_MAX;
    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // Print error if socket failed
    if (sockfd < 0) {
	fprintf(stdout, "Socket() failed");
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
	fprintf(stdout, "setsockopt() failed"); 
	fflush(stdout); 
	exit(-1); 
    } 

    // Network functions need arguments in network byte order instead of
    // host byte order. The macros htonl, htons convert the values.
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(32000);
    funcError = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
    
    // Handle error if bind() fails
    if (funcError < 0) {
	fprintf(stdout, "bind() failed"); 
	fflush(stdout); 
	exit(-1); 
    }
    // Before the server can accept messages, it has to listen to the
    // welcome port. A backlog of one connection is allowed.
    funcError = listen(sockfd, 1);
    // Handle error if listen() fails
    if (funcError < 0) {
	fprintf(stdout, "listen() failed"); 
	fflush(stdout); 
	exit(-1); 
    }

    // Initialize the pollfd structure 
    memset(pollfds, 0, sizeof(pollfds));
    pollfds[0].fd = sockfd; 
    pollfds[0].events = POLLIN; 
    // TImeout???
    
    for (;;) {
        
	funcError = poll(pollfds, nfds, timeout);   

	// We first have to accept a TCP connection, connfd is a fresh
        // handle dedicated to this connection.
        socklen_t len = (socklen_t) sizeof(client);
        int connfd = accept(sockfd, (struct sockaddr *) &client, &len);

        // Receive from connfd, not sockfd.
        ssize_t n = recv(connfd, message, sizeof(message) - 1, 0);

        message[n] = '\0';
        fprintf(stdout, "Received:\n%s\n", message);

        // Convert message to upper case.
        for (int i = 0; i < n; ++i) message[i] = toupper(message[i]);

        // Send the message back.
        send(connfd, message, (size_t) n, 0);

        // Close the connection.
        shutdown(connfd, SHUT_RDWR);
        close(connfd);
    }
}
