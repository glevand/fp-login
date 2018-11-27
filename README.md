```
fp-login
SYNOPSIS
     fp-login [-a, --auth-format auth-format] [-c, --certificate certificate]
              [-C, --config config] [-f, --favorite-id favorite-id]
              [-h, --help] [-H, --host host] [-n, --nameserver nameserver]
              [-N, --network network] [-p, --port port] [-u, --user user]
              [-v, --verbose] [-V, --version]
DESCRIPTION
     The fp-login client is used to remotely log into a FirePass VPN server.
OPTIONS
     -a, --auth-format auth-format
             Specifies the format of the authentication data sent to the VPN
             server.  The default auth-format is ’U:P’.
     -c, --certificate certificate
             Use the x509 certificate file certificate.
     -C, --config config
             Use the configuration file config.  Use of this option will cause
             fp-login to bypass processing of its default configuration files.
     -f, --favorite-id favorite-id
             Connect to the FirePass VPN with the favorite ID favorite-id.
             The default favorite-id is ’Z=0,1’.  This will work for most
             VPNs.
     -h, --help
             Print a help message.
     -H, --host host
             Connect to the remote FirePass VPN server host.
     -n, --nameserver nameserver
             Add the name server nameserver to the local resolver configura-
             tion. This option specifies the DNS nameservers for the remote
             network, and can be specified multiple times.  The current imple-
             mentation only supports a single --nameserver option.
     -N, --network network
             Add the remote network network to the local routing tables for this
             VPN connection. Must be in the 'target/prefix' format.
     -p, --port port
             Use the remote FirePass server port port.  The default port value
             is 443 (https).
     -u, --user user
             Use the user login name user.
     -v, --verbose
             Program verbosity level. The level is additive. -vvv will give a
             verbose output.
     -V, --version
             Display the program version number.
     See the fp-login man page for more info.
     Send bug reports to Geoff Levand <geoff@infradead.org>
```
