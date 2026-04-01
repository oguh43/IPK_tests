# L4 Scanner Test Environment

## How to connect
In order to have IPv6 support FITVPN must be used. You may succeed with connecting via kolejnet alone but this configuration is **deprecated** since 30.4.2026!

This service will be live from assignment date up until your final grades (including pathes / manual review). This way you can use this tool in your automated tests.

### Linux
Congratulations, just use FITVPN and you are set! Don't forget to use the interface `tun0`.

### Windows

#### WSL2
Install FITVPN on your host OS **AND** inside wsl itself. Use interface `tun0`. UDP may be broken due to VPN configuration.

#### QUEMU VM - preferred
Install FITVPN only on your host OS. Interace will remain unchanged (for example: `enp6s0`).


## Support
If you encounter issues:
 - Feel free to contact me on discord (pm / tag in ipk-private)
 - Unsupported configurations (those not listed here) **will have minimal to no support**! If you get it working, you may create a pull request and add the instructions here.