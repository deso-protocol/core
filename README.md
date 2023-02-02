![DeSo Logo](assets/camelcase_logo.svg)

# About DeSo
DeSo is a blockchain built from the ground up to support a fully-featured
social network. Its architecture is similar to Bitcoin, only it supports complex
social network data like profiles, posts, follows, creator coin transactions, and
more.

[Read about the vision](https://docs.deso.org/the-vision)

# About this Repo

This repo contains all of the consensus code for the DeSo protocol. While it can 
technically be built and run as a stand-alone binary, it is mainly intended to be
"composed" into other projects that want to build on top of DeSo. We provide
multiple examples of how to do this in this README.

# Building on DeSo Core

Below we provide a few real-world examples of how to compose DeSo core into your project.

## Example 1: A Standard DeSo App (e.g. [diamond](https://diamondapp.com) or [desofy](https://desofy.app))

The code that powers DeSo apps like [node.deso.org](https://node.deso.org) is fully open-source
such that anyone in the world can run it, and it consists of three repositories:
* **[github.com/deso-protocol/backend](https://github.com/deso-protocol/backend)**
* **[github.com/deso-protocol/frontend](https://github.com/deso-protocol/frontend)**
* **[github.com/deso-protocol/identity](https://github.com/deso-protocol/identity)**

The repo that is most interesting for understanding the role of DeSo core is
[backend](https://github.com/deso-protocol/backend) because it effectively includes core
as a library to run a node. Then, it builds on core's basic functionality to expose
[a rich API](https://docs.deso.org/devs/backend-api) of its own that can be used to 
construct transactions, submit transactions to the network, manage user data, and 
much more.

The backend repo's API is then utilized by
[frontend](https://github.com/deso-protocol/frontend) and 
[identity](https://github.com/deso-protocol/identity), which are Angular apps that are
served as the frontend to apps like [node.deso.org](https://node.deso.org).

## Example 2: A Rosetta API for Exchange Listing

[Rosetta](https://rosetta-api.org) is an API developed by Coinbase and used by
exchanges all over the world to list coins. For most modern exchanges, implementing a
Rosetta API makes it a breeze to integrate a coin because all of their infrastructure
can plug into a standardized interface.

Because exchanges have a different set of needs than what's required to run a 
DeSo web app, composing core allowed us
to build a fully Dockerized Rosetta API that conforms perfectly to spec as its own
self-contained service. This allows exchanges to integrate DeSo without having
to run the unnecessary services associated with serving node.deso.org.

For more information on the DeSo Rosetta API, see our rosetta-deso repo here:
* **[https://github.com/deso-protocol/rosetta-deso](https://github.com/deso-protocol/rosetta-deso)**

## Example 3: A MongoDB Data Dumper

Another example of composing the core repo is the DeSo MongoDB Dumper.
* **[github.com/deso-protocol/mongodb-dumper](https://github.com/deso-protocol/mongodb-dumper)**

This tool does the following:
* It includes core as a library
* It uses its embedded core code to download all of the blockchain data
* It takes all of the blockchain data and indexes it into MongoDB

This gives users the ability to query all of the chain data using the MongoDB
commandline tool, or to layer a product like Retool on top of it.

# Running DeSo Core

Because core is intended to be composed into other projects, we suggest that
users who want to run it start by reading [the README in the backend repo](https://github.com/deso-protocol/backend)
mentioned previously. This repo provides instructions on how set up a dev environment
for a full frontend and backend stack that can serve a full clone 
of apps like [node.deso.org](https://node.deso.org) with one's own custom feed.

We also provide a [run repo](https://github.com/deso-protocol/run) that shows how to 
run this full stack in a fully Dockerized production environment.

# Acknowledgements

The architecture for DeSo was heavily-inspired by Bitcoin. We also owe a debt
of gratitude to the developers of [btcd](https://github.com/btcsuite/btcd) for
producing a truly amazing Go Bitcoin client that served as a reference when
building DeSo.
