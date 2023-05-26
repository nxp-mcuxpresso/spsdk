FlexSPI Configuration Block (FCB)
""""""""""""""""""""""""""""""""""""""""
The FCB will configure the settings of the FlexSPI communication. It will establish how many ports will be used, what clock speed to run the FlexSPI controller at, etc. This is the first thing that happens, as everything else is stored in Flash memory. In order to read anything else, the flash must first be configured.

.. include:: ../_prebuild/fcb_schemas.inc
   :parser: myst_parser.sphinx_
