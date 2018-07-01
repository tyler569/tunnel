
## Tunnel

A simple VPN built using a Linux TUN adapter

### Usage

I would highly reccomend changing the hardcoded key in the code (`hexkey`) if you plan on using this for anything.

Deploy the same binary to the client and server, then run these commands:

Server: `./tunnel --server --addr <server cidr>`

Client: `./tunnel --addr <client cidr> --remote <remote ip>`

##### Examples -

`./tunnel --server --addr 10.200.0.1/24`

`./tunnel --addr 10.200.0.10/24 --remote 1.2.3.4`

In that example, any traffic sent to 10.200.0.10 on the server will go to the client and any traffic on the client to 10.200.0.1 will go to the server.  You can then bind servers to those IPs or permit IP forwarding in the linux kernel to use one end as a router.  In the same vein, you can use the linux routing table to send traffic through the tunnel.

### Options

`--server` : sets this instance as the server (listens for a connection instead of connecting out)

`--addr <cidr>` : sets the address and mask of the TUN adapter for this side of the tunnel

`--remote` : tells the client what to connect to

`--port` : sets the port for the server to listen on or the client to connect to.

### Future plans

- Key generation and automatic rotation
- IKE / ISAKMP
- More ciphers
- More flexability
- Support for more than one simultanious client on the server
