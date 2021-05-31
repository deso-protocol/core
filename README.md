![BitClout Logo](https://bitclout.com/assets/img/camelcase_logo.svg)

# About BitClout
BitClout is a blockchain built from the ground up to support a fully-featured
social network. Its architecture is similar to Bitcoin, only it supports complex
social network data like profiles, posts, follows, creator coin transactions, and
more.

[Read about the vision](https://docs.bitclout.com/the-vision)

# About this Repo

This repo contains all of the consensus code for the BitClout protocol. While it can 
technically be built and run as a stand-alone binary, it is mainly intended to be
"composed" into other projects that want to build on top of BitClout. We provide
multiple examples of how to do this in this README.

# Building on BitClout Core

Below we provide a few real-world examples of how to compose BitClout core into your project.

## Example 1: A BitClout Website (aka [bitclout.com](https://bitclout.com))

The code that powers [bitclout.com](https://bitclout.com) is fully open-source
such that anyone in the world can run it, and it consists of three repositories:
* **[github.com/bitclout/backend](https://github.com/bitclout/backend)**
* **[github.com/bitclout/frontend](https://github.com/bitclout/frontend)**
* **[github.com/bitclout/identity](https://github.com/bitclout/identity)**

The repo that is most interesting for understanding the role of BitClout core is
[backend](https://github.com/bitclout/backend) because it effectively includes core
as a library and [uses its public API](https://FIXME)
to run a node. Then, it builds on core's basic
functionality to expose [a rich API](https://FIXME) of its own that can be used to 
construct transactions, submit transactions to the network, manage user data, and 
much more.

The backend repo's API is then utilized by
[frontend](https://github.com/bitclout/frontend) and 
[identity](https://github.com/bitclout/identity), which are Angular apps that are
served as the frontend to [bitclout.com](https://bitclout.com).

## Example 2: A Rosetta API for Exchange Listing

[Rosetta](https://rosetta-api.org) is an API developed by Coinbase and used by
exchanges all over the world to list coins. For most modern exchanges, implementing a
Rosetta API makes it a breeze to integrate a coin because all of their infrastructure
can plug into a standardized interface.

Because exchanges have a different set of needs than what's required to run a 
BitClout web app, composing core allowed us
to build a fully Dockerized Rosetta API that conforms perfectly to spec as its own
self-contained service. This allows exchanges to integrate BitClout without having
to run the unnecessary services associated with serving bitclout.com.

For more information on the BitClout Rosetta API, see our bitclout-rosetta repo here:
* **[https://github.com/bitclout/rosetta-bitclout](https://github.com/bitclout/rosetta-bitclout)**

## Example 3: A MongoDB Data Dumper

Another example of composing the core repo is the BitClout MongoDB Dumper.
* **[github.com/bitclout/mongodb-dumper](https://github.com/bitclout/mongodb-dumper)**

This tool does the following:
* It includes core as a library
* It uses its embedded core code to download all of the blockchain data
* It takes all of the blockchain data and indexes it into MongoDB

This gives users the ability to query all of the chain data using the MongoDB
commandline tool, or to layer a product like Retool on top of it.

# Running BitClout Core

Because core is intended to be composed into other projects, we suggest that
users who want to run it start by reading [the README in the backend repo](https://github.com/bitclout/backend)
mentioned previously. This repo provides instructions on how set up a dev environment
for a full frontend and backend stack that can serve a full clone 
of [bitclout.com](https://bitclout.com) with one's own custom feed.

We also provide a [run repo](https://github.com/bitclout/run) that shows how to 
run this full stack in a fully Dockerized production environment.

# Acknowledgements

The architecture for BitClout was heavily-inspired by Bitcoin. We also owe a debt
of gratitude to the developers of [btcd](https://github.com/btcsuite/btcd) for
producing a truly amazing Go Bitcoin client that served as a reference when
building BitClout.
