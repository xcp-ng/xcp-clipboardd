# xcp-clipboardd

Share clipboard between Windows VM (called **guest**) and VNC client (called **host**) running elsewhere and which is connected to QEMU. QEMU in turn acts as the VNC server for this Windows VM.
In other words: xcp-clipboardd is a resident program which is launched at guest start in dom0, and which makes the necessary protocol conversion to make the clipboard sharing possible.


## Build

Run these commands in the project directory:

```bash
mkdir build
cd build
cmake ..
make
```

## Other Requirements

The Windows guest should have `win-xenguestagent` installed.

# How does it work?

In Xen architecture, QEMU, amongst other tasks, can act as VNC server and thus allows a VNC client to connect to the guest.
Even if clipboard sharing is part of the VNC protocol, in Xen world it is not used as is for some technical debt reasons. Only the communication with the VNC client follows this protocol for this need.
The communication with Windows guests is done through the XenStore protocol. That is, xcp-clipboardd uses a socket provided by QEMU to communicate with the host/client and uses the XenStore (special nodes and events) to communicate with the guest.
On the other hand, on the guest, `win-xenguestagent` is responsible for reading/writing to the appropriate XenStore nodes and to use Windows API to communicate with Windows' clipboard.

## Copying clipboard data from host/client to guest

* The **host/client** clipboard changes.
    * VNC protocol (when configured to do so) communicates the data to QEMU VNC server.
    * QEMU writes this data to a socket which xcp-clipboardd listens to.
    * xcp-clipboardd, after retrieving the data from QEMU, does some small conversion (for protocol needs) and writes it to a dedicated XenStore node.
    * win-xenguestagent on its hand is notified that the data is available on the XenStore node, retrieves it, and uses Windows API to communicate with Windows' clipboard. 

## Copying clipboard data from guest to host/client

* The **guest** clipboard changes. 
    * win-xenguestagent is notified and retrieves the clipboard data through Windows API. 
    * win-xenguestagent writes the data to a dedicated XenStore node and the data is retrieved by xcp-clipboardd.
    * xcp-clipboardd does some small protocol conversion and writes to QEMU socket.
    * QEMU VNC server sends the data to VNC client.

# Would you like to know more?

A forked QEMU (`qemu-trad.pg`) in XenServer has a similar code to this scenario that you can see [here](https://github.com/xenserver/qemu-trad.pg/blob/0c3bd1feb0b8efff6fc592ee8b5c06a25ebbcff4/master/vnc_clipboard.patch). `xcp-clipboardd` cannot work without this code in `qemu-trad.pg`.
