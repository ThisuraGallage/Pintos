#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "list.h"
#include "process.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h" /* Imports shutdown_power_off() for use in halt(). */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;



void syscall_init (void) 
{
  
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/*
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
*/

static void
syscall_handler(struct intr_frame* f)
{
  
  //first check if f->esp is a valid pointer)
  if(!(f->esp < PHYS_BASE) || f->esp == NULL || f->esp < (void *) 0x08048000)
    {
      /* Terminate the program and free its resources */
      
      exit(-1);
    }



  //cast f->esp into an int*, then dereference it for the SYS_CODE
  switch(*(int*)f->esp)
  {
    case SYS_HALT:
    //Implement syscall EXIT
    {
    
    shutdown_power_off();
    break;
    }


    case SYS_EXIT:
    {

    //Implement syscall EXIT

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    int status = *(arg1_address);
    exit(status);
    break;
    }



    case SYS_EXEC:
    {

    //Implement syscall EXEC

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }
    if (!isValidAddress((void*)*arg1_address)){
      exit(-1);
    }

    f->eax = exec((void*)*arg1_address);
    break;
    }


    case SYS_WAIT:
    {

    //Implement syscall WAIT

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    f->eax = process_wait(*arg1_address);
    break;
    }


    case SYS_CREATE:
    {

    //Implement syscall CREATE

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    int* arg2_address=(int*)f->esp + 2;
    if (!isValidAddress(arg2_address)){
      exit(-1);
    }

    f->eax = create((void*)(*((int*)f->esp + 1)),*arg2_address);

    break;
    }


    case SYS_REMOVE:
    {

    //Implement syscall REMOVE

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    f->eax = remove((void*)(*((int*)f->esp + 1)));

    break;
    }


    case SYS_OPEN:
    {

    //Implement syscall OPEN

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    f->eax = open((void*)(*((int*)f->esp + 1)));

    break;
    }


    case SYS_FILESIZE:
    {

    //Implement syscall FILESIZE

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    f->eax = filesize(*arg1_address);
    
    break;
    }


    case SYS_READ:
    {

    //Implement syscall READ

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    int* arg2_address=(int*)f->esp + 2;
    if (!isValidAddress(arg2_address)){
      exit(-1);
    }

    int* arg3_address=(int*)f->esp + 3;
    if (!isValidAddress(arg3_address)){
      exit(-1);
    }

      
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);

      f->eax = read(fd, buffer, size);
    break;
    }


    case SYS_WRITE:
    {

      //Implement syscall WRITE

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    int* arg2_address=(int*)f->esp + 2;
    if (!isValidAddress(arg2_address)){
      exit(-1);
    }

    int* arg3_address=(int*)f->esp + 3;
    if (!isValidAddress(arg3_address)){
      exit(-1);
    }

      
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);

      f->eax = write(fd, buffer, size);
      break;
    }


    case SYS_SEEK:
    {

    //Implement syscall SEEK
    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }

    int* arg2_address=(int*)f->esp + 2;
    if (!isValidAddress(arg2_address)){
      exit(-1);
    }  
    
    
    break;
    }


    case SYS_TELL:
    {

    //Implement syscall TELL
    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
    }
    
    f->eax = tell(*arg1_address);
  
    break;
    }


    case SYS_CLOSE:
    {

    //Implement syscall CLOSE

    int* arg1_address=(int*)f->esp + 1;
    if (!isValidAddress(arg1_address)){
      exit(-1);
      
    }

    close(*arg1_address);
    break;
    }

  }
}




bool isValidAddress(void *ptr){

  if(!is_user_vaddr(ptr) || (void *)0x08048003>ptr){
    return false;
  }
  if(pagedir_get_page (thread_current()->pagedir, ptr)==NULL){
    return false;
  }
  if (ptr==NULL){
    return false;
  }
  return true;

}

void exit (int status){

    struct list_elem *child_list_element;
    for (child_list_element = list_begin (&thread_current()->parent->children); child_list_element != list_end (&thread_current()->parent->children);
        child_list_element = list_next (child_list_element))
      {
        struct child *child_object = list_entry (child_list_element, struct child, elem);
        if(child_object->tid == thread_current()->tid)
        {
          child_object->times_used = 1;
          child_object->exit_code = status;
        }
      }

	  thread_current()->exit_code = status;
	  printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit ();
}



tid_t exec(const char* cmd_line){

  lock_acquire(&filesys_lock);

  char * save_ptr;
  char * f_name = strtok_r((char *)cmd_line, " ", &save_ptr); 
  struct file* fl = filesys_open (f_name);

  if(fl==NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }  

  file_close(fl);
  tid_t tid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return tid;

}





//filesystem

bool create(const char *file, unsigned initial_size){
  if (!isValidAddress((void*)file)){
    exit(-1);
    return false;
  }
  else if(*file==""){
    exit(-1);
    return false;
  }
  lock_acquire(&filesys_lock);
  bool created=filesys_create(file,initial_size);
  lock_release(&filesys_lock);
  return created;
}

bool remove (const char *file){
  if (!isValidAddress((void*)file)){
    exit(-1);
    return false;
  }
  lock_acquire(&filesys_lock);
  bool removed=filesys_remove(file);
  lock_release(&filesys_lock);
  return removed;
}

int open (const char *file){
 
  if (!isValidAddress((void*)file)){
   
    exit(-1);
    return -1;
  }
  else if(file==""){
  
    exit(0);
    return 0;
  }
  lock_acquire(&filesys_lock);
  struct file *f=filesys_open(file);
 
  int fd_i;
  if (f==NULL){
 
    fd_i=0;
    lock_release(&filesys_lock);
    exit(0);
    return fd_i;
  }
  
  
  fd_i=thread_current()->next_fd_i;
  thread_current()->next_fd_i+=1;
  thread_current()->file_discriptor_table[fd_i]=f;
  
  lock_release(&filesys_lock);
  return fd_i;
  
}

int filesize (int fd){
  lock_acquire(&filesys_lock);
  if(thread_current()->file_discriptor_table[fd]!=NULL){
  int size=file_length(thread_current()->file_discriptor_table[fd]);
  lock_release(&filesys_lock);
  return size;
  }
  else{
    exit(-1);
    return -1;    
  }
}

int read (int fd, void *buffer, unsigned size){

  if (!isValidAddress((void*)buffer)){
 
    exit(-1);
    return -1;
  }

  if (fd == 0) 
  {

    lock_acquire(&filesys_lock);
    for (unsigned i = 0; i < size; i++){
      //(uint8_t *)buffer=input_getc();
      //buffer[i]=input_getc();
      *((uint8_t *)buffer++) = input_getc ();      
    }
    lock_release(&filesys_lock);
    return size;
  }
  else if(thread_current()->file_discriptor_table[fd]!=NULL){
 
    lock_acquire(&filesys_lock);
    int bytes_read=(int)file_read(thread_current()->file_discriptor_table[fd],buffer,size);
    lock_release(&filesys_lock);
    return bytes_read;
  }
  else{
 
    exit(-1);    
    return -1;    
  }
}

int write (int fd, const void *buffer, unsigned size){
  if (!isValidAddress((void*)buffer)){
    exit(-1);
    return -1;
  }
  lock_acquire(&filesys_lock);
  if(fd == 1)
	{
		putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
	}
  else if (fd == 0)
  {
    lock_release(&filesys_lock);
    return 0;
  }
  else if(thread_current()->file_discriptor_table[fd]!=NULL){
      int bytes_written = (int) file_write(thread_current()->file_discriptor_table[fd], buffer, size);
      lock_release(&filesys_lock);
      return bytes_written;
  }
  else{
    exit(-1);
    return -1;    
  }
}

void seek (int fd, unsigned position){
 if(thread_current()->file_discriptor_table[fd]!=NULL){
  lock_acquire(&filesys_lock);
  file_seek (thread_current()->file_discriptor_table[fd], position);
  lock_release(&filesys_lock);
  }
  else{
    exit(-1);
  }
};

unsigned tell (int fd){
if(thread_current()->file_discriptor_table[fd]!=NULL){
  lock_acquire(&filesys_lock);
  int ret=file_tell(thread_current()->file_discriptor_table[fd]);
  lock_release(&filesys_lock);
  return ret;
  }
  else{
    exit(-1);
    return -1;
  }
};

void close (int fd){
  
  
  lock_acquire(&filesys_lock);
  if(thread_current()->file_discriptor_table[fd]!=NULL){
   
    file_close(thread_current()->file_discriptor_table[fd]);
    thread_current()->file_discriptor_table[fd]=NULL;
  }
  else{
 
  exit (-1);
  }
  lock_release(&filesys_lock); 
};

