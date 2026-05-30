#include "fd_utils.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "logging.h"

bool fdutil_write_fd(int sock, int fd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  char data = 0;

  struct iovec iov = {
    .iov_base = &data,
    .iov_len = sizeof(data),
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf),
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg) return false;

  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

  if (sendmsg(sock, &msg, 0) == -1) {
    LOGE("sendmsg failed with %d: %s", errno, strerror(errno));

    return false;
  }

  return true;
}

int fdutil_read_fd(int sock) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  char data = 0;

  struct iovec iov = {
    .iov_base = &data,
    .iov_len = sizeof(data),
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf),
  };

  ssize_t ret;
  do {
    ret = recvmsg(sock, &msg, MSG_WAITALL);
  } while (ret == -1 && errno == EINTR);

  if (ret == -1) {
    LOGE("recvmsg failed with %d: %s", errno, strerror(errno));

    return -1;
  }

  int fd = -1;
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) continue;

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

    break;
  }

  if (fd == -1)
    LOGE("Failed to receive fd: no valid fd found in ancillary data");

  return fd;
}
