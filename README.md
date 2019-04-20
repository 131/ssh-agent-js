[![Build Status](https://travis-ci.org/131/ssh-agent-js.svg?branch=master)](https://travis-ci.org/131/ssh-agent-js)
[![Coverage Status](https://coveralls.io/repos/github/131/ssh-agent-js/badge.svg?branch=master)](https://coveralls.io/github/131/ssh-agent-js?branch=master)
[![Version](https://img.shields.io/npm/v/ssh-agent-js.svg)](https://www.npmjs.com/package/ssh-agent-js)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)

[![Code style](https://img.shields.io/badge/code%2fstyle-ivs-green.svg)](https://www.npmjs.com/package/eslint-plugin-ivs)



# Motivation
A pure js drop-in replacement for ssh-agent.
This agent is a replacement for the ssh-agent program. This package includes both a **"server"** and **"client"** API. This library implements the official agent protocol and is compatible with all ssh clients (ssh & putty)



# Client API

## new Agent(socket)
## await agent.list_keys();
## await agent.add_key(<Buffer> privateKey [, <string> alias]);
## await agent.remove_key(<Buffer> pubkey || <string> alias || <string> fingerprint);
## await agent.remove_all_keys();
## await agent.sign(<string> alias || <string> fingerprint, <Buffer> message);




# Credits
* [131](https://github.com/131)
* yks ssh-agent https://github.com/131/yks/blob/master/class/apis/ssh_agent.php
* https://tools.ietf.org/html/draft-miller-ssh-agent-00
* https://github.com/131/pageantbridge
