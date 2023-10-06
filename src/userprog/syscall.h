#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>


typedef int tid_t;

void syscall_init (void);

int write (int fd, const void *buffer, unsigned size);
bool isValidAddress(void *ptr);
void exit (int status);
tid_t exec(const char* cmd_line);




//file system
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);



#endif /* userprog/syscall.h */

