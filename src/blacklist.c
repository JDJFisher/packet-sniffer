#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "blacklist.h"

typedef struct blacklist
{
    unsigned int length;
    const char** hosts;
} blacklist;

static blacklist bl;

int is_blacklisted(const char* host)
{
    if (host == NULL) return 0;

    // For each host in the blacklist
    size_t i;
    for(i = 0; i < bl.length; i++)
    {   // If the blacklist contains a substring of the provided host return true
        if(strstr(host, bl.hosts[i]) != NULL) return 1;
    }

    // The host name is not in the blacklist
    return 0;
}

void blacklist_load(const char* file_path, int verbose)
{
    if (verbose) printf("Loading blacklist... ");

    // Open file handle
    FILE* fptr;
    fptr = fopen(file_path, "r");
    if(fptr == NULL)
    {
        perror("Unable to load blacklist");
        exit(EXIT_FAILURE);
    }

    // Count the number of lines
    unsigned int count = 0;
    char c;
    for (c = getc(fptr); c != EOF; c = getc(fptr))
    {
        if (c == '\n')  count++;
    }

    // Allocate space for the host names
    bl.hosts = malloc(count * sizeof(char*));
    bl.length = count;

    char *line = NULL;
	size_t len, read;

    // Return line pointer to the beginning of the file
    rewind(fptr);

    // Read the hosts from the file into the host array line-by-line
    unsigned int i = 0;
    while ((read = getline(&line, &len, fptr)) != -1)
    {
        read -= 2; // remove '\n'
        char* host = calloc(read + 1, sizeof(char));
        strncpy(host, line, read);
        bl.hosts[i++] = host;
	}

    // Cleanup 
    free(line);
    fclose(fptr);

    if (verbose) printf("done\n");
}

void blacklist_destroy()
{
    // Free all of the memory allocated for the host names
    unsigned int i = 0;
    for (i = 0; i < bl.length; i++)
    {
        free((char*) bl.hosts[i]);
    }

    // Free the space allocated for the string array
    free(bl.hosts);
    bl.hosts = NULL;
}
