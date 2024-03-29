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
    // A GOptionContext struct defines which options are accepted by the commandline option parser
    GOptionContext *context;
    GError *error = NULL;

    // Set the name of our HTTP server
    context = g_option_context_new ("Emru Can server\n");
    g_option_context_add_main_entries(context, entries, NULL);  

    // Check if the parsing was successful
    if (!g_option_context_parse(context, &argc, &argv, &error))
    {
      g_critical("Parsing failed: %s:%s\n", argv[0], error->message);
      exit(0);
    }
    
    int port, sockfd = -1, funcError, on = 1, nfds = 1, currSize, newfd = -1, i, j;
    struct sockaddr_in server;
    char buffer[1024];
    struct pollfd pollfds[200];
    int timeout = 30*1000;
    int endServer = FALSE, shrinkArray = FALSE, closeConn = FALSE;
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
		    pollfds[nfds].revents = POLLIN; 
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
		    
		    funcError = recv(pollfds[i].fd, buffer, sizeof(buffer), 0); 

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

		    // DO STUFF HER
		    fprintf(stdout, "THIS IS NOT A LISTENING CONNECTION ATTEND TO ME \n"); 
		    fflush(stdout); 

		} while (TRUE); 

	   }
	    fprintf(stdout, "hello after for-loop. do we make it here?\n"); 
	    fflush(stdout);  
	    if (closeConn) {
		// Clean up connections that were closed
		close(pollfds[i].fd);
		pollfds[i].fd = -1; 
		shrinkArray = TRUE; 
	    }
	}
	fprintf(stdout, "after do while (I think?)\n"); 
	fflush(stdout); 
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

	fprintf(stdout, "after shrinkarray\n"); 
	fflush(stdout); 
        /*
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
	*/
    }
}
