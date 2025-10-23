.. _tlv_blob:

=========
TLV Blob
=========

Introduction
=============

TLV (Type-Length-Value) Blob is a data structure used in SPSDK for storing and transmitting data in a flexible and extensible format. It consists of:

- **Type**: Identifies the kind of data being stored
- **Length**: Specifies the size of the value field
- **Value**: Contains the actual data

TLV Blobs are commonly used in various NXP device configurations and secure boot implementations.

Usage
======

TLV Blobs can be created and manipulated using the SPSDK API or through the nxpimage command-line tool.


Supported Devices
==================

TLV Blob format is supported by various NXP devices. For a complete list of supported devices and their capabilities,
refer to the devices list documentation.
