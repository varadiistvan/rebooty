# Reboot your home server after you messed up and lost SSH connection!

I often find myself in the situation where I updated ssh or fucked around and found out, locking myself out of my home server until I get my housemate to reboot it. 
To same them from this trouble, I decided to take it into my own hands. So as long as this server is running on my server, I can reboot whenever I want!

## Installation
You can install this package using cargo:
```
$ cargo install --git https://github.com/varadiistvan/rebooty --locked
```
Alternatively, you can clone this repo and install it locally
```
$ git clone https://github.com/varadiistvan/rebooty
$ cargo install --path ./rebooty
```

## Usage
You can start the server using the `booty` command. Upon startup, it will print out the port it's running on, as well as the expected MAC address (just ignore the first ':'). 
You can specify a port with the `PORT` environmental variable.

To reboot your computer, send a UDP packet to the given port (52424 by default), which contains the MAC address and an RSA signature of the MAC address with a private key, for which the public key is in `$HOME/.ssh/authorized_keys`.
Note that you don't need to be running an ssh server for it.

Additionally, this message should be encrypted using AES256, with the nonce and the key appended to the message, encrypted with the earlier used RSA key.

tl;dr the message looks like this:
```
{AES256encrypt(key, nonce, "{MAC}{RSAsign(private_rsa_key, MAC)}")RSAencrypt(private_rsa_key, "{nonce}{key}")}
```

The executable (or the user) needs to be given boot permissions to work! It can be easily given to the executable using

```
$ sudo setcap CAP_SYS_BOOT+ep ~/.cargo/bin/booty
```

## Security

This reboot server is vulnerable to a replay attack, letting an attacker reboot your server whenever they please, so avoid using it on networks where you could be listened to!
