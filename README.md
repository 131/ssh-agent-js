# ssh-agent
A pure js drop-in replacement for ssh-agent.


# Motivation
This agent is a replacement for the ssh-agent program. This package includes both a "server" and "client" API.
This API is used by the project nwagent (a node-webkit project for desktops).
This library implements the official agent protocol (http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent?rev=HEAD) and is therefore compatible with all ssh clients (ssh & putty)


# Implementations
ssh-agent relies on named pipes (linux only). For windows platforms, the putty/plink/pscp/.. stack relies on winAPI sendmessage/postmessage & memorymap. This is handled by the https://github.com/131/pageantbridge project.



# Credits
* Inspirations from mcavage ssh-agent for clients binding
* yks ssh-agent https://github.com/131/yks/blob/master/class/apis/ssh_agent.php

