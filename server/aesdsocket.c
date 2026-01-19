
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
static volatile int exit_requested = 0;

static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM){
        printf("Signal %d received, setting exit_requested flag\n", signo);
        syslog(LOG_INFO, "Caught signal, exiting");
         exit_requested = 1;
    }
       
}
//Modify your program to support a -d argument which runs the aesdsocket application as a daemon. When in daemon mode the program should fork after ensuring it can bind to port 9000.
int main( int argc, char *argv[])
{
    int daemon_mode = 0;
    // Check for -d argument
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        daemon_mode = 1;
    }
     struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

 //Opens a stream socket bound to port 9000, failing and returning -1 if any of the socket connection steps fail.
    int sockfd;
    struct addrinfo hints, *servinfo;
    char ipstr[INET6_ADDRSTRLEN];
    socklen_t sin_size;


   

    if (sigaction(SIGINT, &sa, NULL) != 0)
    {
        perror("sigaction SIGINT");
         return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0)
    {
        perror("sigaction SIGTERM");
        return -1;
    }

    memset(&hints, 0, sizeof(hints)); // Clear the hints structure

    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;     // allow the IP to be assigned automatically

    // print getaddrinfo to debug

    printf("Getting address info...\n");
    int gai = getaddrinfo(NULL, "9000", &hints, &servinfo);
    if (gai != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return -1;
    }

    printf("Creating socket...\n");
    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }
    // Set socket options to allow reuse of address
    int yes = 1;
    // Lose the pesky "address already in use" error message
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
               sizeof(int));
    printf("Binding socket...\n");
    int b = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
    if (b < 0)
    {
        perror(" bind");
        return -1;
    }
    // If daemon mode, fork the process
    if (daemon_mode)
    {
        printf("Running in daemon mode, forking process...\n");
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            return -1;
        }
        if (pid > 0)
        {
            // Parent process, exit
            printf("Daemon process started with PID %d\n", pid);
            exit(0);
        }
        // Child process continues
        printf("In daemon process with PID %d\n", getpid());
    }
    // Free the address info structure
    printf("Freeing address info...\n");
    freeaddrinfo(servinfo);
    printf("Listening for incoming connections...\n");
    // Listening for incoming connections with a backlog of 5
    int lre = listen(sockfd, 5);
    if (lre < 0)
    {
        perror("listen");
        return -1;
    }
    printf("Accepting a connection...\n");
    while (!exit_requested)
    {
        /* code */

        struct sockaddr client_addr;
        sin_size = sizeof(client_addr);
        int new_fd = accept(sockfd, &client_addr, &sin_size);
        char *buffer = NULL;

        if (new_fd < 0)
        {
            
            perror("accept");
            printf("Accept failed, checking for exit request...\n");
            break;
        }
        inet_ntop(client_addr.sa_family,
                  &((struct sockaddr_in *)&client_addr)->sin_addr,
                  ipstr, sizeof(ipstr));
        printf("Accepted connection from %s\n", ipstr);
        syslog(LOG_INFO, "Accepted connection from %s", ipstr);
        // Logs message to the syslog “Accepted connection from xxx” where XXXX is the IP address of the connected client.
        // Receives data over the connection and appends to file /var/tmp/aesdsocket
         
        size_t initial_size = 1024;
        size_t used_size = 0;
        size_t total_size = initial_size;
        char *nl = NULL;
        ssize_t bytes_received = 0;
        size_t pkt_len = 0;
        int packet_complete = 0;

        buffer = malloc(total_size);
        if (buffer == NULL)
        {
            perror("malloc");
            close(new_fd);
            syslog(LOG_INFO, "Closed connection from %s", ipstr);
            break;
        }
        memset(buffer, 0, total_size);

        while (!packet_complete)
        {
            nl = memchr(buffer, '\n', used_size);
            if (nl != NULL)
            {
                // Newline found, stop receiving
                pkt_len = (size_t)(nl - buffer) + 1;
                packet_complete = 1;
                break;
            }
            // if nl is NULL, continue receiving
            // Resize buffer if needed
            if (used_size >= total_size)
            {
                total_size += initial_size;
                char *tmp = realloc(buffer, total_size);

                if (!tmp)
                {
                    perror("realloc");

                    break;
                }
                buffer = tmp;
            }

            bytes_received = recv(new_fd, buffer + used_size, total_size - used_size, 0);

            if (bytes_received < 0)
            {
                
                perror("recv");

                break;
            }

            else if (bytes_received == 0)
            {
                // Connection closed by client

                break;
            }
            else
            {
                used_size += (size_t)bytes_received;
                continue;
            }
        }
         if (packet_complete)
        {

            // print received data for debug
            printf("Received %zd bytes\n", pkt_len);
            printf("Data: %.*s\n", (int)pkt_len, buffer);
            // use a newline to separate data packets received.  then use the result to append to the /var/tmp/aesdsocketdata file.

            FILE *file = fopen("/var/tmp/aesdsocketdata", "a");
            if (file == NULL)
            {
                printf("Failed to open /var/tmp/aesdsocketdata for appending\n");
                perror("fopen");
             
                 
            }else{
                printf("Appending data to /var/tmp/aesdsocketdata\n");
            fwrite(buffer, 1, pkt_len, file);
            fclose(file);}
                printf("Data appended to /var/tmp/aesdsocketdata\n");
            // Sends the complete contents of /var/tmp/aesdsocketdata back over the connection
            FILE *read_file = fopen("/var/tmp/aesdsocketdata", "r");
            if (read_file == NULL)
            {
                perror("fopen");
                 
              
            }else{
                printf("Sending data back to client...\n");
            char file_buffer[1024];
            size_t bytes_read;
            while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), read_file)) > 0)
            {
                printf("Sending %zu bytes\n", bytes_read);
                size_t bytes_sent = 0;
                while (bytes_sent < bytes_read)
                {
                    ssize_t n = send(new_fd, file_buffer + bytes_sent, bytes_read - bytes_sent, 0);
printf("Sent %zd bytes\n", n);
                    if (n < 0)
                    
                    {
                    
                        perror("send");
                        break;
                    }
                    // handle case where n == 0
                    if (n == 0)
                    {
                        break;
                    }
                    bytes_sent += (size_t)n;
                    
                }
               
            }
            printf("Data sent back to client\n");
            fclose(read_file);
            }
            printf("Finished handling client %s\n", ipstr);
            free(buffer);
            buffer = NULL;
        }
        // Closes the connection
        // Logs message to the syslog “Closed connection from XXX” where XXX is the IP address of the connected client.
         printf("Closing connection from %s\n", ipstr);
        if (buffer)
        {
            free(buffer);
        }
        printf("Connection from %s closed\n", ipstr);
        close(new_fd);
        syslog(LOG_INFO, "Closed connection from %s", ipstr);
    }

    if (exit_requested)
    {
        printf("Exit requested, shutting down...\n");
        syslog(LOG_INFO, "Caught signal, exiting");
    }
    printf("Closing server socket...\n");
    close(sockfd);

    // Delete the /var/tmp/aesdsocketdata file
    printf("Deleting /var/tmp/aesdsocketdata...\n");
    if (remove("/var/tmp/aesdsocketdata") != 0)
    {
        perror("remove");
        printf("Failed to delete /var/tmp/aesdsocketdata\n");
    }

    return 0;
}
