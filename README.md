# xcp-clipboardd

Share clipboard between guest Windows and host with VNC.
More explicit: xcp-clipboardd is a binary file that allows to copy & paste between a VNC client, called **host** in the document, and a virtualized Windows, called **guest**.

## Build

Run these commands in the project directory:

```bash
mkdir build
cd build
cmake ..
make
```

# How does it work?

The working of the binary is based on the listening of `POLLIN` on 2 sockets: one furnished by QEMU, called `qEmuFd` in this document, and another by XenStore, called `xsFd`.

## Copying code from guest to host

* The **guest** clipboard changes.
    * The `xsFd` socket is notified with `POLLIN`.
    * We then check the token given by XenStore, it should be `report_clipboard` in this scenario.
    * If this is the case, we read the XenStore and writes the size of the data and the data into `qEmuFd`.

## Copying code from host to guest

* The basic scenario is when the clipboard of the **host** changes.
    * The `qEmuFd` is notified with `POLLIN`.
    * We read what's in the `qEmuFd`: the size of data on 4 bytes and the data.
    * Then we write the data, chunk by chunk, into the Xenstore.
* A second scenario is when the data from the previous one have not been completely written.
    * The `xsFd` socket is notified with `POLLIN`.
    * We then check the token given by XenStore, it should be `set_clipboard` in this scenario.
    * We read what's in the `qEmuFd`: the size of the data on 4 bytes and the data.
    * Then we write the data, chunk by chunk, into the Xenstore.

# Would you like to know more?

A forked QEMU (`qemu-trad.pg`) in XenServer has a similar code to this scenario that you can see [here](https://github.com/xenserver/qemu-trad.pg/blob/0c3bd1feb0b8efff6fc592ee8b5c06a25ebbcff4/master/vnc_clipboard.patch). `xcp-clipboardd` cannot work without this code in `qemu-trad.pg`.
