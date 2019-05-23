/* xcp-clipboardd: Share clipboard between guest Windows and host with VNC.
 *
 * Copyright (C) 2019  ronan.abhamon@vates.fr (Vates SAS)
 * Copyright (C) 2019  benjamin.reis@vates.fr (Vates SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE // getopt_long
#define __USE_GNU // POLLRDHUP

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <xenstore.h>

#include <xcp-ng/generic.h>

#define MIN(A, B) (((A) < (B)) ? (A) : (B))

// =============================================================================

#define CLIPBOARD_SET_NODE "set_clipboard"
#define CLIPBOARD_REPORT_NODE "report_clipboard"

// -----------------------------------------------------------------------------
// Buffer API.
// -----------------------------------------------------------------------------

// See: https://zinascii.com/2014/the-8-byte-two-step.html
#define BUFFER_ALIGN_SIZE(SIZE, BLOCK_SIZE) \
  (((SIZE) + ((BLOCK_SIZE) - 1)) & ~((BLOCK_SIZE) - 1))

typedef struct {
  size_t capacity;
  size_t size;
  void *data;
  size_t blockSize;
} Buffer;

static int bufferReserve (Buffer *buffer, size_t size) {
  if (buffer->capacity < buffer->size) {
    syslog(LOG_ERR, "bad buffer attributes: (capacity = %zu) < (size = %zu)", buffer->capacity, buffer->size);
    return -1;
  }

  if (buffer->capacity - buffer->size >= size)
    return 0; // Enough space in buffer.

  buffer->capacity = BUFFER_ALIGN_SIZE(buffer->size + size, buffer->blockSize);
  void *newBuffer = realloc(buffer->data, buffer->capacity);
  if (!newBuffer) {
    syslog(LOG_ERR, "out of memory to realloc buffer with %zu bytes", buffer->capacity);
    return -1;
  }
  buffer->data = newBuffer;
  return 0;
}

static void bufferReset (Buffer *buffer) {
  buffer->capacity = 0;
  buffer->size = 0;
  free(buffer->data);
  buffer->data = NULL;
}

static int bufferAppend (Buffer *buffer, const void *data, size_t size) {
  if (bufferReserve(buffer, size) == -1)
    return -1;
  memcpy((char *)buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 0;
}

// -----------------------------------------------------------------------------

static int safeWrite (int fd, const void *buf, size_t count) {
  if (xcp_fd_write_all(fd, buf, count, NULL) < 0) {
    syslog(LOG_ERR, "unable to write properly in %d because: %s", fd, strerror(errno));
    return -1;
  }

  return 0;
}

// -----------------------------------------------------------------------------

#define BUILD_FULL_PATH(XS, DOM_ID, NODE, FULL_PATH) \
  do { \
    char *domainPath = xs_get_domain_path(XS, DOM_ID); \
    if (!domainPath || asprintf(&FULL_PATH, "%s/data/" NODE, domainPath) == -1) { \
      syslog(LOG_ERR, "unable to get full " NODE " path"); \
      FULL_PATH = NULL; \
    } \
    free(domainPath); \
  } while (0)

static struct {
  size_t size;
  size_t offset;
  void *data;
  char needReset;
} ClipboardState;

// Writing host chunk to guest.
static int xenStoreSetClipboardEvent (struct xs_handle *xs, unsigned int domId) {
  char *fullPath;
  BUILD_FULL_PATH(xs, domId, CLIPBOARD_SET_NODE, fullPath);
  if (!fullPath) return -1;

  char *chunk = xs_read(xs, XBT_NULL, fullPath, NULL);
  if (chunk) {
    // Still waiting for the guest to read the pending chunk.
    free(chunk);
    goto end;
  }

  if (!ClipboardState.needReset) {
    if (!ClipboardState.data)
      goto end; // Nothing to write for now.

    unsigned int len = (unsigned int)MIN(ClipboardState.size - ClipboardState.offset, 1024);
    syslog(LOG_DEBUG, "writing chunk to guest clipboard (count=%u)", len);
    if (!xs_write(xs, XBT_NULL, fullPath, (char *)ClipboardState.data + ClipboardState.offset, len)) {
      free(fullPath);
      syslog(LOG_ERR, "error while writing chunk to guest clipboard because: %s", strerror(errno));
      return -1;
    }

    if (!len) {
      syslog(LOG_DEBUG, "writing to guest clipboard has been completed");
      free(ClipboardState.data);
      memset(&ClipboardState, 0, sizeof ClipboardState);
    } else
      ClipboardState.offset += len;
  } else {
    // Reset report_clipboard value.
    if (!xs_write(xs, XBT_NULL, fullPath, "", 0)) {
      free(fullPath);
      syslog(LOG_ERR, "unable to reset guest clipboard because: %s", strerror(errno));
      return -1;
    }
    ClipboardState.needReset = 0;
  }

end:
  free(fullPath);

  return 0;
}

// -----------------------------------------------------------------------------

// Copying from host to guest.
static int writeGuestClipboard (struct xs_handle *xs, unsigned int domId, void *buf, size_t count) {
  if (ClipboardState.data)
    ClipboardState.needReset = 1;

  void *dest = NULL;
  if (count) {
    if (!(dest = malloc(count))) {
      syslog(LOG_ERR, "not enough memory to alloc guest clipboard buffer");
      return -1;
    }
    memcpy(dest, buf, count);
  }

  ClipboardState.size = count;
  ClipboardState.offset = 0;
  free(ClipboardState.data);
  ClipboardState.data = dest;

  return xenStoreSetClipboardEvent(xs, domId);
}

#define HOST_CLIPBOARD_SIZE_LIMIT (1024 * 1024) // 1MiB

// Copying from Guest to Host.
static int writeHostClipboard (struct xs_handle *xs, int qemuFd, unsigned int domId) {
  char *fullPath;
  BUILD_FULL_PATH(xs, domId, CLIPBOARD_REPORT_NODE, fullPath);
  if (!fullPath) return -1;

  unsigned int len;
  char *chunk = xs_read(xs, XBT_NULL, fullPath, &len);
  if (!chunk)
    goto end; // No data for now.

  static Buffer buffer = { 0, 0, NULL, 64 };
  static char bufferLimitReached = 0;

  if (!len) {
    // We have all the data. We can write in the host.
    if (buffer.data && !bufferLimitReached) {
      syslog(LOG_DEBUG, "flush to host clipboard (count=%zu)", buffer.size);
      safeWrite(qemuFd, &buffer.size, sizeof(uint32_t));
      safeWrite(qemuFd, buffer.data, buffer.size);
    }
    bufferReset(&buffer);
    bufferLimitReached = 0;
  } else if (BUFFER_ALIGN_SIZE(buffer.size + len, buffer.blockSize) <= HOST_CLIPBOARD_SIZE_LIMIT) {
    syslog(LOG_DEBUG, "writing chunk to host clipboard (count=%u)", len);
    bufferAppend(&buffer, chunk, len);
  } else
    bufferLimitReached = 1;

  free(chunk);
  xs_rm(xs, XBT_NULL, fullPath);

end:
  free(fullPath);

  return 0;
}

// -----------------------------------------------------------------------------

typedef int (*FdHandler)(struct xs_handle *xs, int qemuFd, unsigned int domId);

static int xenStoreHandler (struct xs_handle *xs, int qemuFd, unsigned int domId) {
  syslog(LOG_DEBUG, "calling %s", __FUNCTION__);

  unsigned int nums;
  char **buf = xs_read_watch(xs, &nums);
  if (!buf) {
    syslog(LOG_ERR, "unable to read watch");
    return -1;
  }

  // Can be NULL, not an error. ;)
  const char *token = buf[XS_WATCH_TOKEN];
  if (!token)
    return 0;

  int ret = -1;

  syslog(LOG_DEBUG, "XenStore token: %s", token);
  if (!strcmp(token, CLIPBOARD_SET_NODE))
    ret = xenStoreSetClipboardEvent(xs, domId); // Called when host copy data to guest.
  else if (!strcmp(token, CLIPBOARD_REPORT_NODE))
    ret = writeHostClipboard(xs, qemuFd, domId); // Called when guest copy data to host.
  else
    syslog(LOG_ERR, "invalid token: %s", token);

  free(buf);
  return ret;
}

// Called when host copy data to guest.
static int guestClipboardHandler (struct xs_handle *xs, int qemuFd, unsigned int domId) {
  syslog(LOG_DEBUG, "calling %s", __FUNCTION__);

  static Buffer buffer = { 0, 0, NULL, 1024 };
  if (bufferReserve(&buffer, 4096) == -1)
    return -1;

  void *pos = (char *)buffer.data + buffer.size;
  XcpError ret = xcp_fd_read(qemuFd, pos, 4096);
  if (ret < 0) {
    syslog(LOG_ERR, "read failed because: %s", strerror(errno));
    return -1;
  } else if (ret == 0) {
    syslog(LOG_ERR, "nothing to read in guest clipboard...");
    return -1;
  }
  buffer.size += (size_t)ret;

  // The first 4-byte contains the buffer's size.
  // We can't start writing the guest clipboard without the full buffer data.
  size_t threshold = sizeof(uint32_t);
  if (buffer.size < threshold)
    return 0;

  threshold += *(uint32_t *)buffer.data;
  if (buffer.size < threshold)
    return 0;

  // Ok. We have the whole data to write. \o/
  if (writeGuestClipboard(xs, domId, (char *)buffer.data + sizeof(uint32_t), threshold - sizeof(uint32_t)) == -1)
    return -1;

  if (buffer.size != threshold)
    memmove(buffer.data, (char *)buffer.data + threshold, buffer.size - threshold);
  buffer.size -= threshold;

  return 0;
}

// -----------------------------------------------------------------------------

static int handleEvents (struct xs_handle *xs, int qemuFd, unsigned int domId) {
  FdHandler handlers[2] = {
    xenStoreHandler,
    guestClipboardHandler
  };

  struct pollfd fds[2] = {
    { xs_fileno(xs), POLLIN, 0 },
    { qemuFd, POLLIN, 0 }
  };

  for (;;) {
    if (xcp_poll(fds, 2, -1) != XCP_ERR_OK) {
      syslog(LOG_ERR, "poll failed because: %s", strerror(errno));
      return -1;
    }

    for (int i = 0; i < 2; ++i) {
      if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL | POLLRDHUP)) {
        syslog(LOG_ERR, "poll failed because revents=0x%x (%s socket)", fds[i].revents, i == 0 ? "xs" : "qemu");
        return -1;
      }

      if (fds[i].revents & POLLIN) {
        fds[i].revents = 0;
        if ((*handlers[i])(xs, qemuFd, domId) == -1)
          return -1;
      }
    }
  }
}

// -----------------------------------------------------------------------------

static int watchXenStoreNode (struct xs_handle *xs, const char *domainPath, const char *leaf) {
  char *buf;
  if (asprintf(&buf, "%s/data/%s", domainPath, leaf) == -1)
    return -1;

  if (!xs_watch(xs, buf, leaf)) {
    free(buf);
    return -1;
  }

  free(buf);
  return 0;
}

static int initXenStore (struct xs_handle *xs, unsigned int domId) {
  char *domainPath = xs_get_domain_path(xs, domId);
  if (
    !domainPath ||
    watchXenStoreNode(xs, domainPath, CLIPBOARD_SET_NODE) == -1 ||
    watchXenStoreNode(xs, domainPath, CLIPBOARD_REPORT_NODE) == -1
  ) {
    free(domainPath);
    return -1;
  }

  free(domainPath);
  return 0;
}

// -----------------------------------------------------------------------------

static void usage (const char *progname) {
  printf("Usage: %s [OPTIONS]\n", progname);
  puts("  -d, --domid                  HVM domid");
  puts("  -s, --qemu-clipboard-fd      the file descriptor of qemu clipboard socket");
  puts("  -h, --help                   print this help and exit");
}

// -----------------------------------------------------------------------------

int main (int argc, char *argv[]) {
  const char *opstring = "hd:s:";
  const struct option longopts[] = {
    { "domid", 1, NULL, 'd' },
    { "qemu-clipboard-fd", 1, NULL, 's' },
    { "help", 0, NULL, 'h' },
    { NULL, 0, 0, 0 }
  };

  unsigned int domId = 0;
  int qemuFd = -1;

  int option;
  int longindex;
  while ((option = getopt_long(argc, argv, opstring, longopts, &longindex)) != -1) {
    switch (option) {
      case 'd':
        if (sscanf(optarg, "%u", &domId) != 1) {
          fprintf(stderr, "Unable to read properly domid.");
          return EXIT_FAILURE;
        }
        break;
      case 's':
        if (sscanf(optarg, "%d", &qemuFd) != 1) {
          fprintf(stderr, "Unable to read properly fd.");
          return EXIT_FAILURE;
        }
        break;
      case 'h':
        usage(argv[0]);
        return EXIT_SUCCESS;
      case '?':
        printf("Try `%s --help' for more information.\n", argv[0]);
        return EXIT_FAILURE;
    }
  }

  // -d and -s are required!
  if (domId == 0 || qemuFd < 0) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  openlog(argv[0], LOG_PID, LOG_DAEMON);

  #ifdef DEBUG
    setlogmask(LOG_UPTO(LOG_DEBUG));
  #else
    setlogmask(LOG_UPTO(LOG_INFO));
  #endif // ifdef DEBUG

  int ret = EXIT_SUCCESS;
  struct xs_handle *xs = NULL;

  if (daemon(0, 0)) {
    syslog(LOG_ERR, "daemon call failed because: %s", strerror(errno));
    goto fail;
  }

  xs = xs_open(0);
  if (!xs) {
    syslog(LOG_ERR, "unable to get xs handle because: %s", strerror(errno));
    goto fail;
  }
  if (initXenStore(xs, domId) == -1) {
    syslog(LOG_ERR, "unable to init XenStore");
    goto fail;
  }

  if (handleEvents(xs, qemuFd, domId) != -1)
    goto end;

fail:
  ret = EXIT_FAILURE;

end:
  xs_close(xs);
  closelog();

  return ret;
}
