-------------------------
Master Boot Image (MBI)
-------------------------

Master Boot Image can be used directly (e.g. by using *blhost write-memory* command) or it can be used for further processing  (e.g. used as input to Secure Binary image container).
Image is created based on a supplied configuration file, either JSON or YAML is supported.

We can divide divide into two categories based on layout.

* eXecute-In-Place (XIP) images
    * Plain
    * CRC
    * Signed

* Load-to-RAM images
    * Plain
    * CRC
    * Signed images with HMAC signed header. Since load-to-RAM copies the image from untrusted media to on-chip RAM, the length field in header should be authenticated before copy. Hence HMAC signed headers are used.
    * Encrypted (plain header with HMAC + AES-CBC encrypted).

Example of use

nxpimage: ``nxpimage mbi export -c <path to config file>``

.. toctree::
    :caption: Master Boot Image
    :maxdepth: 1

    ../../examples/_knowledge_base/mbi_summary
    mbi_supported_images
