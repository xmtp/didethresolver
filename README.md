# didethresolver

[![Test](https://github.com/xmtp/didethresolver/actions/workflows/ci-image.yml/badge.svg)](https://github.com/xmtp/didethresolver/actions/workflows/ci-image.yml)

This resolver service implements a DID registry resolver to resolve decentralized identifiers for the XMTP client sdk.

## Introduction to DID Specification

The Decentralized Identifiers (DIDs) v1.0 specification, as outlined by W3C, describes a system for creating verifiable, decentralized digital identities. DIDs are unique identifiers that can refer to any subject, such as a person or organization, and are controlled by their creator rather than a centralized authority. This approach aims to decouple identity management from centralized registries and certificate authorities.

Key aspects of DIDs include:

1. **Decentralization**: DIDs eliminate reliance on centralized authorities for identifier management. They offer a way to manage digital identities without a single point of failure

2. **Control and Privacy**: Entities can directly control their digital identifiers and manage the privacy of their information, including what personal data is revealed in different contexts

3. **Interoperability and Portability**: DIDs are designed to be interoperable and can be used across different systems and networks. This promotes a seamless experience across various digital platforms

4. **Architecture**: The architecture of DIDs involves several components, including DID subjects (the entities identified by the DIDs), DID controllers (those who have the capability to make changes to a DID document), and verifiable data registries (systems that record DIDs and DID documents for resolution)

5. **Conformance**: The specification outlines conformance criteria for different components of the DID ecosystem, including DIDs, DID documents, DID resolvers, and DID URL dereferencers. Conformance ensures that these components operate consistently within the DID infrastructure

## Reference Implementation

* [Veramo Labs](https://github.com/veramolabs/did-eth/tree/main/packages/did-eth-resolver)

## Quick Start (Dev Containers)

This project supports containerized development. From Visual Studio Code Dev Containers extension specify the Dockerfile as the target:

`Reopen in Container`

or

Command line build using docker

```bash
$ docker build . -t didethresolver:1
```
