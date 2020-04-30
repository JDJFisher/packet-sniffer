#ifndef CS241_BLACKLIST_H
#define CS241_BLACKLIST_H

int is_blacklisted(const char* host);
void blacklist_load(const char* file_path, int verbose);
void blacklist_destroy();

#endif
