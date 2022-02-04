# Mbi_PlainXip

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.

```yaml
# ===========  YAML template Mbi_PlainXip  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_CrcXip

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.

```yaml
# ===========  YAML template Mbi_CrcXip  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_SignedXip

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`mainCertPrivateKeyFile`** *(string)*: Main Certificate private key used to sign certificate.
- **`imageBuildNumber`** *(['number', 'string'])*: If it's omitted, it will be used 0 as default value.
- **`chainCertificate0File0`** *(string)*: Chain certificate 0 for root certificate 0.
- **`chainCertificate0File1`** *(string)*: Chain certificate 1 for root certificate 0.
- **`chainCertificate0File2`** *(string)*: Chain certificate 2 for root certificate 0.
- **`chainCertificate0File3`** *(string)*: Chain certificate 3 for root certificate 0.
- **`chainCertificate1File0`** *(string)*: Chain certificate 0 for root certificate 1.
- **`chainCertificate1File1`** *(string)*: Chain certificate 1 for root certificate 1.
- **`chainCertificate1File2`** *(string)*: Chain certificate 2 for root certificate 1.
- **`chainCertificate1File3`** *(string)*: Chain certificate 3 for root certificate 1.
- **`chainCertificate2File0`** *(string)*: Chain certificate 0 for root certificate 2.
- **`chainCertificate2File1`** *(string)*: Chain certificate 1 for root certificate 2.
- **`chainCertificate2File2`** *(string)*: Chain certificate 2 for root certificate 2.
- **`chainCertificate2File3`** *(string)*: Chain certificate 3 for root certificate 2.
- **`chainCertificate3File0`** *(string)*: Chain certificate 0 for root certificate 3.
- **`chainCertificate3File1`** *(string)*: Chain certificate 1 for root certificate 3.
- **`chainCertificate3File2`** *(string)*: Chain certificate 2 for root certificate 3.
- **`chainCertificate3File3`** *(string)*: Chain certificate 3 for root certificate 3.
- **`mainCertChainId`** *(['number', 'string'])*: Index of chain certificate that is used as a main.
- **`rootCertificate0File`** *(string)*: Root certificate file index 0.
- **`rootCertificate1File`** *(string)*: Root certificate file index 1.
- **`rootCertificate2File`** *(string)*: Root certificate file index 2.
- **`rootCertificate3File`** *(string)*: Root certificate file index 3.
- **`mainRootCertId`** *(['number', 'string'])*: Index of certificate that is used as a main.

```yaml
# ===========  YAML template Mbi_SignedXip  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
#  
#  == Certificate V2 Settings == 
#  
mainCertPrivateKeyFile: my_prv_key.pem # [Optional], Main Certificate private key, Main Certificate private key used to sign certificate
imageBuildNumber: 0 # [Optional], Image Build Number, If it's omitted, it will be used 0 as default value.
chainCertificate0File0: chain_certificate0_depth0.pem # [Optional], Chain certificate 0 for root 0, Chain certificate 0 for root certificate 0
chainCertificate0File1: chain_certificate0_depth1.pem # [Optional], Chain certificate 1 for root 0, Chain certificate 1 for root certificate 0
chainCertificate0File2: chain_certificate0_depth2.pem # [Optional], Chain certificate 2 for root 0, Chain certificate 2 for root certificate 0
chainCertificate0File3: chain_certificate0_depth3.pem # [Optional], Chain certificate 3 for root 0, Chain certificate 3 for root certificate 0
chainCertificate1File0: chain_certificate1_depth0.pem # [Optional], Chain certificate 0 for root 1, Chain certificate 0 for root certificate 1
chainCertificate1File1: chain_certificate1_depth1.pem # [Optional], Chain certificate 1 for root 1, Chain certificate 1 for root certificate 1
chainCertificate1File2: chain_certificate1_depth2.pem # [Optional], Chain certificate 2 for root 1, Chain certificate 2 for root certificate 1
chainCertificate1File3: chain_certificate1_depth3.pem # [Optional], Chain certificate 3 for root 1, Chain certificate 3 for root certificate 1
chainCertificate2File0: chain_certificate2_depth0.pem # [Optional], Chain certificate 0 for root 2, Chain certificate 0 for root certificate 2
chainCertificate2File1: chain_certificate2_depth1.pem # [Optional], Chain certificate 1 for root 2, Chain certificate 1 for root certificate 2
chainCertificate2File2: chain_certificate2_depth2.pem # [Optional], Chain certificate 2 for root 2, Chain certificate 2 for root certificate 2
chainCertificate2File3: chain_certificate2_depth3.pem # [Optional], Chain certificate 3 for root 2, Chain certificate 3 for root certificate 2
chainCertificate3File0: chain_certificate3_depth0.pem # [Optional], Chain certificate 0 for root 3, Chain certificate 0 for root certificate 3
chainCertificate3File1: chain_certificate3_depth1.pem # [Optional], Chain certificate 1 for root 3, Chain certificate 1 for root certificate 3
chainCertificate3File2: chain_certificate3_depth2.pem # [Optional], Chain certificate 2 for root 3, Chain certificate 2 for root certificate 3
chainCertificate3File3: chain_certificate3_depth3.pem # [Optional], Chain certificate 3 for root 3, Chain certificate 3 for root certificate 3
mainCertChainId: 0 # [Optional], Main Certificate Chain Index, Index of chain certificate that is used as a main.
#  
#  == Certificate Settings == 
#  
rootCertificate0File: my_certificate0.pem # [Required], Root Certificate File 0, Root certificate file index 0.
rootCertificate1File: my_certificate1.pem # [Optional], Root Certificate File 1, Root certificate file index 1.
rootCertificate2File: my_certificate2.pem # [Optional], Root Certificate File 2, Root certificate file index 2.
rootCertificate3File: my_certificate3.pem # [Optional], Root Certificate File 3, Root certificate file index 3.
mainRootCertId: 0 # [Optional], Main Certificate Index, Index of certificate that is used as a main.

```
# Mbi_PlainXipRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.

```yaml
# ===========  YAML template Mbi_PlainXipRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_CrcXipRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.

```yaml
# ===========  YAML template Mbi_CrcXipRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_PlainSignedXipRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`mainCertPrivateKeyFile`** *(string)*: Main Certificate private key used to sign certificate.
- **`imageBuildNumber`** *(['number', 'string'])*: If it's omitted, it will be used 0 as default value.
- **`chainCertificate0File0`** *(string)*: Chain certificate 0 for root certificate 0.
- **`chainCertificate0File1`** *(string)*: Chain certificate 1 for root certificate 0.
- **`chainCertificate0File2`** *(string)*: Chain certificate 2 for root certificate 0.
- **`chainCertificate0File3`** *(string)*: Chain certificate 3 for root certificate 0.
- **`chainCertificate1File0`** *(string)*: Chain certificate 0 for root certificate 1.
- **`chainCertificate1File1`** *(string)*: Chain certificate 1 for root certificate 1.
- **`chainCertificate1File2`** *(string)*: Chain certificate 2 for root certificate 1.
- **`chainCertificate1File3`** *(string)*: Chain certificate 3 for root certificate 1.
- **`chainCertificate2File0`** *(string)*: Chain certificate 0 for root certificate 2.
- **`chainCertificate2File1`** *(string)*: Chain certificate 1 for root certificate 2.
- **`chainCertificate2File2`** *(string)*: Chain certificate 2 for root certificate 2.
- **`chainCertificate2File3`** *(string)*: Chain certificate 3 for root certificate 2.
- **`chainCertificate3File0`** *(string)*: Chain certificate 0 for root certificate 3.
- **`chainCertificate3File1`** *(string)*: Chain certificate 1 for root certificate 3.
- **`chainCertificate3File2`** *(string)*: Chain certificate 2 for root certificate 3.
- **`chainCertificate3File3`** *(string)*: Chain certificate 3 for root certificate 3.
- **`mainCertChainId`** *(['number', 'string'])*: Index of chain certificate that is used as a main.
- **`rootCertificate0File`** *(string)*: Root certificate file index 0.
- **`rootCertificate1File`** *(string)*: Root certificate file index 1.
- **`rootCertificate2File`** *(string)*: Root certificate file index 2.
- **`rootCertificate3File`** *(string)*: Root certificate file index 3.
- **`mainRootCertId`** *(['number', 'string'])*: Index of certificate that is used as a main.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.

```yaml
# ===========  YAML template Mbi_PlainSignedXipRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
#  
#  == Certificate V2 Settings == 
#  
mainCertPrivateKeyFile: my_prv_key.pem # [Optional], Main Certificate private key, Main Certificate private key used to sign certificate
imageBuildNumber: 0 # [Optional], Image Build Number, If it's omitted, it will be used 0 as default value.
chainCertificate0File0: chain_certificate0_depth0.pem # [Optional], Chain certificate 0 for root 0, Chain certificate 0 for root certificate 0
chainCertificate0File1: chain_certificate0_depth1.pem # [Optional], Chain certificate 1 for root 0, Chain certificate 1 for root certificate 0
chainCertificate0File2: chain_certificate0_depth2.pem # [Optional], Chain certificate 2 for root 0, Chain certificate 2 for root certificate 0
chainCertificate0File3: chain_certificate0_depth3.pem # [Optional], Chain certificate 3 for root 0, Chain certificate 3 for root certificate 0
chainCertificate1File0: chain_certificate1_depth0.pem # [Optional], Chain certificate 0 for root 1, Chain certificate 0 for root certificate 1
chainCertificate1File1: chain_certificate1_depth1.pem # [Optional], Chain certificate 1 for root 1, Chain certificate 1 for root certificate 1
chainCertificate1File2: chain_certificate1_depth2.pem # [Optional], Chain certificate 2 for root 1, Chain certificate 2 for root certificate 1
chainCertificate1File3: chain_certificate1_depth3.pem # [Optional], Chain certificate 3 for root 1, Chain certificate 3 for root certificate 1
chainCertificate2File0: chain_certificate2_depth0.pem # [Optional], Chain certificate 0 for root 2, Chain certificate 0 for root certificate 2
chainCertificate2File1: chain_certificate2_depth1.pem # [Optional], Chain certificate 1 for root 2, Chain certificate 1 for root certificate 2
chainCertificate2File2: chain_certificate2_depth2.pem # [Optional], Chain certificate 2 for root 2, Chain certificate 2 for root certificate 2
chainCertificate2File3: chain_certificate2_depth3.pem # [Optional], Chain certificate 3 for root 2, Chain certificate 3 for root certificate 2
chainCertificate3File0: chain_certificate3_depth0.pem # [Optional], Chain certificate 0 for root 3, Chain certificate 0 for root certificate 3
chainCertificate3File1: chain_certificate3_depth1.pem # [Optional], Chain certificate 1 for root 3, Chain certificate 1 for root certificate 3
chainCertificate3File2: chain_certificate3_depth2.pem # [Optional], Chain certificate 2 for root 3, Chain certificate 2 for root certificate 3
chainCertificate3File3: chain_certificate3_depth3.pem # [Optional], Chain certificate 3 for root 3, Chain certificate 3 for root certificate 3
mainCertChainId: 0 # [Optional], Main Certificate Chain Index, Index of chain certificate that is used as a main.
#  
#  == Certificate Settings == 
#  
rootCertificate0File: my_certificate0.pem # [Required], Root Certificate File 0, Root certificate file index 0.
rootCertificate1File: my_certificate1.pem # [Optional], Root Certificate File 1, Root certificate file index 1.
rootCertificate2File: my_certificate2.pem # [Optional], Root Certificate File 2, Root certificate file index 2.
rootCertificate3File: my_certificate3.pem # [Optional], Root Certificate File 3, Root certificate file index 3.
mainRootCertId: 0 # [Optional], Main Certificate Index, Index of certificate that is used as a main.

```
# Mbi_PlainRamRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`outputImageExecutionAddress`** *(['number', 'string'])*: Application loading address if not XiP.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.

```yaml
# ===========  YAML template Mbi_PlainRamRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
outputImageExecutionAddress: 0 # [Required], Loading address of application., Application loading address if not XiP.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_CrcRamRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`app_table`** *(array)*: This is software future of RTxxx family that NXP SDK startup code(not ROM) could load additional images.
  - **Items** *(object)*
    - **`binary`** *(string)*: The binary file to be added to final application.
    - **`destAddress`** *(['string', 'number'])*: Destination address in RAM of additional binary.
    - **`load`** *(boolean)*: Enabler to load/use the image.
- **`outputImageExecutionAddress`** *(['number', 'string'])*: Application loading address if not XiP.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`outputImageEncryptionKeyFile`** *(string)*: The output image encryption key (file path).
- **`useKeyStore`** *(boolean)*: Enables using key store on device.
- **`deviceKeySource`** *(string)*: Determinate where the keystore is located. There is two options: OTP or KEYSTORE (included in Load to RAM image). Must be one of: `['OTP', 'Keystore']`.
- **`keyStoreFile`** *(string)*: Optional KeyStore data file for included keystore (KEYSTORE source)in LoadToRam images.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.

```yaml
# ===========  YAML template Mbi_CrcRamRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
app_table: # [Optional], The list of additional binaries., This is software future of RTxxx family that NXP SDK startup code(not ROM) could load additional images.
  - my_additional_binary.bin
  - 536870912
  - true
outputImageExecutionAddress: 0 # [Required], Loading address of application., Application loading address if not XiP.
family: lpc55s6x # [Required], MCU family., MCU family name.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
#  
#  == Signing Settings == 
#  
outputImageEncryptionKeyFile: my_encryption_key.bin # [Optional], The output image encryption file used also for HMAC., The output image encryption key (file path).
#  
#  == Encryption Settings == 
#  
useKeyStore: false # [Optional], The Key store enabler., Enables using key store on device.
deviceKeySource: OTP # [Optional], The Key store location., Determinate where the keystore is located. There is two options: OTP or KEYSTORE (included in Load to RAM image).
keyStoreFile: my_key_store_data.bin # [Optional], The Key store data file., Optional KeyStore data file for included keystore (KEYSTORE source)in LoadToRam images.

```
# Mbi_PlainSignedRamRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`app_table`** *(array)*: This is software future of RTxxx family that NXP SDK startup code(not ROM) could load additional images.
  - **Items** *(object)*
    - **`binary`** *(string)*: The binary file to be added to final application.
    - **`destAddress`** *(['string', 'number'])*: Destination address in RAM of additional binary.
    - **`load`** *(boolean)*: Enabler to load/use the image.
- **`outputImageExecutionAddress`** *(['number', 'string'])*: Application loading address if not XiP.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`mainCertPrivateKeyFile`** *(string)*: Main Certificate private key used to sign certificate.
- **`imageBuildNumber`** *(['number', 'string'])*: If it's omitted, it will be used 0 as default value.
- **`chainCertificate0File0`** *(string)*: Chain certificate 0 for root certificate 0.
- **`chainCertificate0File1`** *(string)*: Chain certificate 1 for root certificate 0.
- **`chainCertificate0File2`** *(string)*: Chain certificate 2 for root certificate 0.
- **`chainCertificate0File3`** *(string)*: Chain certificate 3 for root certificate 0.
- **`chainCertificate1File0`** *(string)*: Chain certificate 0 for root certificate 1.
- **`chainCertificate1File1`** *(string)*: Chain certificate 1 for root certificate 1.
- **`chainCertificate1File2`** *(string)*: Chain certificate 2 for root certificate 1.
- **`chainCertificate1File3`** *(string)*: Chain certificate 3 for root certificate 1.
- **`chainCertificate2File0`** *(string)*: Chain certificate 0 for root certificate 2.
- **`chainCertificate2File1`** *(string)*: Chain certificate 1 for root certificate 2.
- **`chainCertificate2File2`** *(string)*: Chain certificate 2 for root certificate 2.
- **`chainCertificate2File3`** *(string)*: Chain certificate 3 for root certificate 2.
- **`chainCertificate3File0`** *(string)*: Chain certificate 0 for root certificate 3.
- **`chainCertificate3File1`** *(string)*: Chain certificate 1 for root certificate 3.
- **`chainCertificate3File2`** *(string)*: Chain certificate 2 for root certificate 3.
- **`chainCertificate3File3`** *(string)*: Chain certificate 3 for root certificate 3.
- **`mainCertChainId`** *(['number', 'string'])*: Index of chain certificate that is used as a main.
- **`rootCertificate0File`** *(string)*: Root certificate file index 0.
- **`rootCertificate1File`** *(string)*: Root certificate file index 1.
- **`rootCertificate2File`** *(string)*: Root certificate file index 2.
- **`rootCertificate3File`** *(string)*: Root certificate file index 3.
- **`mainRootCertId`** *(['number', 'string'])*: Index of certificate that is used as a main.
- **`outputImageEncryptionKeyFile`** *(string)*: The output image encryption key (file path).
- **`useKeyStore`** *(boolean)*: Enables using key store on device.
- **`deviceKeySource`** *(string)*: Determinate where the keystore is located. There is two options: OTP or KEYSTORE (included in Load to RAM image). Must be one of: `['OTP', 'Keystore']`.
- **`keyStoreFile`** *(string)*: Optional KeyStore data file for included keystore (KEYSTORE source)in LoadToRam images.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.

```yaml
# ===========  YAML template Mbi_PlainSignedRamRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
app_table: # [Optional], The list of additional binaries., This is software future of RTxxx family that NXP SDK startup code(not ROM) could load additional images.
  - my_additional_binary.bin
  - 536870912
  - true
outputImageExecutionAddress: 0 # [Required], Loading address of application., Application loading address if not XiP.
family: lpc55s6x # [Required], MCU family., MCU family name.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
#  
#  == Certificate V2 Settings == 
#  
mainCertPrivateKeyFile: my_prv_key.pem # [Optional], Main Certificate private key, Main Certificate private key used to sign certificate
imageBuildNumber: 0 # [Optional], Image Build Number, If it's omitted, it will be used 0 as default value.
chainCertificate0File0: chain_certificate0_depth0.pem # [Optional], Chain certificate 0 for root 0, Chain certificate 0 for root certificate 0
chainCertificate0File1: chain_certificate0_depth1.pem # [Optional], Chain certificate 1 for root 0, Chain certificate 1 for root certificate 0
chainCertificate0File2: chain_certificate0_depth2.pem # [Optional], Chain certificate 2 for root 0, Chain certificate 2 for root certificate 0
chainCertificate0File3: chain_certificate0_depth3.pem # [Optional], Chain certificate 3 for root 0, Chain certificate 3 for root certificate 0
chainCertificate1File0: chain_certificate1_depth0.pem # [Optional], Chain certificate 0 for root 1, Chain certificate 0 for root certificate 1
chainCertificate1File1: chain_certificate1_depth1.pem # [Optional], Chain certificate 1 for root 1, Chain certificate 1 for root certificate 1
chainCertificate1File2: chain_certificate1_depth2.pem # [Optional], Chain certificate 2 for root 1, Chain certificate 2 for root certificate 1
chainCertificate1File3: chain_certificate1_depth3.pem # [Optional], Chain certificate 3 for root 1, Chain certificate 3 for root certificate 1
chainCertificate2File0: chain_certificate2_depth0.pem # [Optional], Chain certificate 0 for root 2, Chain certificate 0 for root certificate 2
chainCertificate2File1: chain_certificate2_depth1.pem # [Optional], Chain certificate 1 for root 2, Chain certificate 1 for root certificate 2
chainCertificate2File2: chain_certificate2_depth2.pem # [Optional], Chain certificate 2 for root 2, Chain certificate 2 for root certificate 2
chainCertificate2File3: chain_certificate2_depth3.pem # [Optional], Chain certificate 3 for root 2, Chain certificate 3 for root certificate 2
chainCertificate3File0: chain_certificate3_depth0.pem # [Optional], Chain certificate 0 for root 3, Chain certificate 0 for root certificate 3
chainCertificate3File1: chain_certificate3_depth1.pem # [Optional], Chain certificate 1 for root 3, Chain certificate 1 for root certificate 3
chainCertificate3File2: chain_certificate3_depth2.pem # [Optional], Chain certificate 2 for root 3, Chain certificate 2 for root certificate 3
chainCertificate3File3: chain_certificate3_depth3.pem # [Optional], Chain certificate 3 for root 3, Chain certificate 3 for root certificate 3
mainCertChainId: 0 # [Optional], Main Certificate Chain Index, Index of chain certificate that is used as a main.
#  
#  == Certificate Settings == 
#  
rootCertificate0File: my_certificate0.pem # [Required], Root Certificate File 0, Root certificate file index 0.
rootCertificate1File: my_certificate1.pem # [Optional], Root Certificate File 1, Root certificate file index 1.
rootCertificate2File: my_certificate2.pem # [Optional], Root Certificate File 2, Root certificate file index 2.
rootCertificate3File: my_certificate3.pem # [Optional], Root Certificate File 3, Root certificate file index 3.
mainRootCertId: 0 # [Optional], Main Certificate Index, Index of certificate that is used as a main.
#  
#  == Signing Settings == 
#  
outputImageEncryptionKeyFile: my_encryption_key.bin # [Optional], The output image encryption file used also for HMAC., The output image encryption key (file path).
#  
#  == Encryption Settings == 
#  
useKeyStore: false # [Optional], The Key store enabler., Enables using key store on device.
deviceKeySource: OTP # [Optional], The Key store location., Determinate where the keystore is located. There is two options: OTP or KEYSTORE (included in Load to RAM image).
keyStoreFile: my_key_store_data.bin # [Optional], The Key store data file., Optional KeyStore data file for included keystore (KEYSTORE source)in LoadToRam images.

```
# Mbi_EncryptedRamRtxxx

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`app_table`** *(array)*: This is software future of RTxxx family that NXP SDK startup code(not ROM) could load additional images.
  - **Items** *(object)*
    - **`binary`** *(string)*: The binary file to be added to final application.
    - **`destAddress`** *(['string', 'number'])*: Destination address in RAM of additional binary.
    - **`load`** *(boolean)*: Enabler to load/use the image.
- **`outputImageExecutionAddress`** *(['number', 'string'])*: Application loading address if not XiP.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`mainCertPrivateKeyFile`** *(string)*: Main Certificate private key used to sign certificate.
- **`imageBuildNumber`** *(['number', 'string'])*: If it's omitted, it will be used 0 as default value.
- **`chainCertificate0File0`** *(string)*: Chain certificate 0 for root certificate 0.
- **`chainCertificate0File1`** *(string)*: Chain certificate 1 for root certificate 0.
- **`chainCertificate0File2`** *(string)*: Chain certificate 2 for root certificate 0.
- **`chainCertificate0File3`** *(string)*: Chain certificate 3 for root certificate 0.
- **`chainCertificate1File0`** *(string)*: Chain certificate 0 for root certificate 1.
- **`chainCertificate1File1`** *(string)*: Chain certificate 1 for root certificate 1.
- **`chainCertificate1File2`** *(string)*: Chain certificate 2 for root certificate 1.
- **`chainCertificate1File3`** *(string)*: Chain certificate 3 for root certificate 1.
- **`chainCertificate2File0`** *(string)*: Chain certificate 0 for root certificate 2.
- **`chainCertificate2File1`** *(string)*: Chain certificate 1 for root certificate 2.
- **`chainCertificate2File2`** *(string)*: Chain certificate 2 for root certificate 2.
- **`chainCertificate2File3`** *(string)*: Chain certificate 3 for root certificate 2.
- **`chainCertificate3File0`** *(string)*: Chain certificate 0 for root certificate 3.
- **`chainCertificate3File1`** *(string)*: Chain certificate 1 for root certificate 3.
- **`chainCertificate3File2`** *(string)*: Chain certificate 2 for root certificate 3.
- **`chainCertificate3File3`** *(string)*: Chain certificate 3 for root certificate 3.
- **`mainCertChainId`** *(['number', 'string'])*: Index of chain certificate that is used as a main.
- **`rootCertificate0File`** *(string)*: Root certificate file index 0.
- **`rootCertificate1File`** *(string)*: Root certificate file index 1.
- **`rootCertificate2File`** *(string)*: Root certificate file index 2.
- **`rootCertificate3File`** *(string)*: Root certificate file index 3.
- **`mainRootCertId`** *(['number', 'string'])*: Index of certificate that is used as a main.
- **`enableHwUserModeKeys`** *(['boolean', 'string'])*: Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
- **`useKeyStore`** *(boolean)*: Enables using key store on device.
- **`deviceKeySource`** *(string)*: Determinate where the keystore is located. There is two options: OTP or KEYSTORE (included in Load to RAM image). Must be one of: `['OTP', 'Keystore']`.
- **`keyStoreFile`** *(string)*: Optional KeyStore data file for included keystore (KEYSTORE source)in LoadToRam images.
- **`outputImageEncryptionKeyFile`** *(string)*: The output image encryption key (file path).
- **`ctr_init_vector`** *(string)*: The initial vector for encryption counter.

```yaml
# ===========  YAML template Mbi_EncryptedRamRtxxx  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
app_table: # [Optional], The list of additional binaries., This is software future of RTxxx family that NXP SDK startup code(not ROM) could load additional images.
  - my_additional_binary.bin
  - 536870912
  - true
outputImageExecutionAddress: 0 # [Required], Loading address of application., Application loading address if not XiP.
family: lpc55s6x # [Required], MCU family., MCU family name.
enableHwUserModeKeys: false # [Required], Enable User HW key sharing., Controlling secure hardware key bus. If enabled(1), then it is possible to access keys on hardware secure bus from non-secure application, else non-secure application will read zeros.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
#  
#  == Certificate V2 Settings == 
#  
mainCertPrivateKeyFile: my_prv_key.pem # [Optional], Main Certificate private key, Main Certificate private key used to sign certificate
imageBuildNumber: 0 # [Optional], Image Build Number, If it's omitted, it will be used 0 as default value.
chainCertificate0File0: chain_certificate0_depth0.pem # [Optional], Chain certificate 0 for root 0, Chain certificate 0 for root certificate 0
chainCertificate0File1: chain_certificate0_depth1.pem # [Optional], Chain certificate 1 for root 0, Chain certificate 1 for root certificate 0
chainCertificate0File2: chain_certificate0_depth2.pem # [Optional], Chain certificate 2 for root 0, Chain certificate 2 for root certificate 0
chainCertificate0File3: chain_certificate0_depth3.pem # [Optional], Chain certificate 3 for root 0, Chain certificate 3 for root certificate 0
chainCertificate1File0: chain_certificate1_depth0.pem # [Optional], Chain certificate 0 for root 1, Chain certificate 0 for root certificate 1
chainCertificate1File1: chain_certificate1_depth1.pem # [Optional], Chain certificate 1 for root 1, Chain certificate 1 for root certificate 1
chainCertificate1File2: chain_certificate1_depth2.pem # [Optional], Chain certificate 2 for root 1, Chain certificate 2 for root certificate 1
chainCertificate1File3: chain_certificate1_depth3.pem # [Optional], Chain certificate 3 for root 1, Chain certificate 3 for root certificate 1
chainCertificate2File0: chain_certificate2_depth0.pem # [Optional], Chain certificate 0 for root 2, Chain certificate 0 for root certificate 2
chainCertificate2File1: chain_certificate2_depth1.pem # [Optional], Chain certificate 1 for root 2, Chain certificate 1 for root certificate 2
chainCertificate2File2: chain_certificate2_depth2.pem # [Optional], Chain certificate 2 for root 2, Chain certificate 2 for root certificate 2
chainCertificate2File3: chain_certificate2_depth3.pem # [Optional], Chain certificate 3 for root 2, Chain certificate 3 for root certificate 2
chainCertificate3File0: chain_certificate3_depth0.pem # [Optional], Chain certificate 0 for root 3, Chain certificate 0 for root certificate 3
chainCertificate3File1: chain_certificate3_depth1.pem # [Optional], Chain certificate 1 for root 3, Chain certificate 1 for root certificate 3
chainCertificate3File2: chain_certificate3_depth2.pem # [Optional], Chain certificate 2 for root 3, Chain certificate 2 for root certificate 3
chainCertificate3File3: chain_certificate3_depth3.pem # [Optional], Chain certificate 3 for root 3, Chain certificate 3 for root certificate 3
mainCertChainId: 0 # [Optional], Main Certificate Chain Index, Index of chain certificate that is used as a main.
#  
#  == Certificate Settings == 
#  
rootCertificate0File: my_certificate0.pem # [Required], Root Certificate File 0, Root certificate file index 0.
rootCertificate1File: my_certificate1.pem # [Optional], Root Certificate File 1, Root certificate file index 1.
rootCertificate2File: my_certificate2.pem # [Optional], Root Certificate File 2, Root certificate file index 2.
rootCertificate3File: my_certificate3.pem # [Optional], Root Certificate File 3, Root certificate file index 3.
mainRootCertId: 0 # [Optional], Main Certificate Index, Index of certificate that is used as a main.
#  
#  == Encryption Settings == 
#  
useKeyStore: false # [Optional], The Key store enabler., Enables using key store on device.
deviceKeySource: OTP # [Optional], The Key store location., Determinate where the keystore is located. There is two options: OTP or KEYSTORE (included in Load to RAM image).
keyStoreFile: my_key_store_data.bin # [Optional], The Key store data file., Optional KeyStore data file for included keystore (KEYSTORE source)in LoadToRam images.
ctr_init_vector: '0xc3df2316fd40b15586cb5ae49483aee2' # [Optional], The output image encryption initial vector for encryption counter., The initial vector for encryption counter.
#  
#  == Signing Settings == 
#  
outputImageEncryptionKeyFile: my_encryption_key.bin # [Required], The output image encryption file used also for HMAC., The output image encryption key (file path).

```
# Mbi_CrcXipLpc55s3x

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`firmwareVersion`** *(['number', 'string'])*: Version of application image firmware.

```yaml
# ===========  YAML template Mbi_CrcXipLpc55s3x  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
firmwareVersion: 0 # [Optional], Firmware version., Version of application image firmware.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_PlainXipSignedLpc55s3x

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`useIsk`** *(boolean)*: Enable ISK type of signature certification.
- **`signingCertificatePrivateKeyFile`** *(string)*: ISK Certificate private key used to sign certificate.
- **`mainRootCertPrivateKeyFile`** *(string)*: Path to Main root Certification Private Key.
- **`signingCertificateFile`** *(string)*: Path to Signing Certificate.
- **`signingCertificateConstraint`** *(['string', 'number'])*: Signing certificate constrain number.
- **`signCertData`** *(string)*: Path to Signing Certificate data.
- **`rootCertificate0File`** *(string)*: Root certificate file index 0.
- **`rootCertificate1File`** *(string)*: Root certificate file index 1.
- **`rootCertificate2File`** *(string)*: Root certificate file index 2.
- **`rootCertificate3File`** *(string)*: Root certificate file index 3.
- **`mainRootCertId`** *(['number', 'string'])*: Index of certificate that is used as a main.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`firmwareVersion`** *(['number', 'string', 'number', 'string'])*: Version of application image firmware.
- **`manifestSigningHashLength`** *(number)*: Optional Manifest signing hash length to create Certificate v3.1 Manifest. Must be one of: `[0, 32, 48, 64]`.

```yaml
# ===========  YAML template Mbi_PlainXipSignedLpc55s3x  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
firmwareVersion: 0 # [Optional], Firmware version., Version of application image firmware.
#  
#  == Certificate V3.1 Settings == 
#  
useIsk: false # [Required], Use ISK for signature certification, Enable ISK type of signature certification
signingCertificatePrivateKeyFile: isk_prv_key.pem # [Conditionally required], ISK Certificate private key, ISK Certificate private key used to sign certificate
mainRootCertPrivateKeyFile: main_cert_prv_key.pem # [Conditionally required], Main root Certification Private Key, Path to Main root Certification Private Key
signingCertificateFile: sign_cert.pem # [Conditionally required], Signing Certificate, Path to Signing Certificate
signingCertificateConstraint: 0 # [Optional], Signing certificate constrain, Signing certificate constrain number
signCertData: sign_cert.bin # [Optional], Signing Certificate data, Path to Signing Certificate data
manifestSigningHashLength: 32 # [Optional], Manifest signing hash length., Optional Manifest signing hash length to create Certificate v3.1 Manifest.
#  
#  == Certificate Settings == 
#  
rootCertificate0File: my_certificate0.pem # [Required], Root Certificate File 0, Root certificate file index 0.
rootCertificate1File: my_certificate1.pem # [Optional], Root Certificate File 1, Root certificate file index 1.
rootCertificate2File: my_certificate2.pem # [Optional], Root Certificate File 2, Root certificate file index 2.
rootCertificate3File: my_certificate3.pem # [Optional], Root Certificate File 3, Root certificate file index 3.
mainRootCertId: 0 # [Optional], Main Certificate Index, Index of certificate that is used as a main.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_PlainRamLpc55s3x

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`outputImageExecutionAddress`** *(['number', 'string'])*: Application loading address if not XiP.
- **`firmwareVersion`** *(['number', 'string'])*: Version of application image firmware.

```yaml
# ===========  YAML template Mbi_PlainRamLpc55s3x  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
outputImageExecutionAddress: 0 # [Required], Loading address of application., Application loading address if not XiP.
firmwareVersion: 0 # [Optional], Firmware version., Version of application image firmware.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_CrcRamLpc55s3x

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`outputImageExecutionAddress`** *(['number', 'string'])*: Application loading address if not XiP.
- **`firmwareVersion`** *(['number', 'string'])*: Version of application image firmware.

```yaml
# ===========  YAML template Mbi_CrcRamLpc55s3x  ===========
#  
#  == Basic Settings == 
#  
inputImageFile: my_application.bin  # [Required], Plain application image., The input application image to by modified to Master Boot Image.
family: lpc55s6x # [Required], MCU family., MCU family name.
outputImageExecutionAddress: 0 # [Required], Loading address of application., Application loading address if not XiP.
firmwareVersion: 0 # [Optional], Firmware version., Version of application image firmware.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# SecureBinary31

- **`firmwareVersion`** *(['number', 'string'])*: Version of application image firmware.
- **`useIsk`** *(boolean)*: Enable ISK type of signature certification.
- **`signingCertificatePrivateKeyFile`** *(string)*: ISK Certificate private key used to sign certificate.
- **`mainRootCertPrivateKeyFile`** *(string)*: Path to Main root Certification Private Key.
- **`rootCertificateEllipticCurve`** *(string)*: Elliptic curve type used for root key. Must be one of: `['secp256r1', 'secp384r1']`.
- **`iskCertificateEllipticCurve`** *(string)*: Elliptic curve type used for ISK key. Must be one of: `['secp256r1', 'secp384r1']`.
- **`signingCertificateFile`** *(string)*: Path to Signing Certificate.
- **`signingCertificateConstraint`** *(['string', 'number'])*: Signing certificate constrain number.
- **`signCertData`** *(string)*: Path to Signing Certificate data.
- **`rootCertificate0File`** *(string)*: Root certificate file index 0.
- **`rootCertificate1File`** *(string)*: Root certificate file index 1.
- **`rootCertificate2File`** *(string)*: Root certificate file index 2.
- **`rootCertificate3File`** *(string)*: Root certificate file index 3.
- **`mainRootCertId`** *(['number', 'string'])*: Index of certificate that is used as a main.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55s3x']`.
- **`containerKeyBlobEncryptionKey`** *(string)*: Path to PCK/NPK key in plain hex string format.
- **`isNxpContainer`** *(boolean)*: Internal usage only, used for generating SB files with NXP content e.g. provisioning firmware, sentinel firmware...
- **`description`** *(string)*: Description up to 16 characters, longer will be truncated by elftosb, stored in SB3.1 manifest. If not provided, inserted elftosb version automatically.
- **`kdkAccessRights`** *(number)*: Accepted values are 0, 1, 2 and 3. Value used as key properties for key derivation process, more details can be in CSSv2 manual.  Once will be development finished, one fixed value will be used and probably not required as user input. Must be one of: `[0, 1, 2, 3]`.
- **`containerConfigurationWord`** *(['string', 'number'])*: Flag value in SB3.1 manifest, not used by silicons with LPC55S3x ROM. Value can be keep 0, or item removed from json file.
- **`commands`** *(array)*: Secure Binary v3.1 commands block, take this list as a full possible example - Modify it regarding your application.
  - **Items** *(object)*
    - **`erase`** *(object)*: Performs a flash erase of the given address range. The erase will be rounded up to the sector size.
      - **`address`** *(['string', 'number'])*: Address of memory block to be erased.
      - **`size`** *(['string', 'number'])*: Size of memory block to be erased.
      - **`memoryId`** *(['string', 'number'])*: ID of memory block to be erased.
    - **`load`** *(object)*: If set, then the data to write immediately follows the range header. The length field contains the actual data length.
      - **`address`** *(['string', 'number'])*: Address of memory block to be loaded.
      - **`memoryId`** *(['string', 'number'])*: ID of memory block to be loaded.
      - **`file`** *(string)*: Binary file to be loaded.
      - **`values`** *(string)*: Binary values delimited by comma to be loaded.
      - **`authentication`** *(string)*: Type of Image authentication [None, cmac, hashlocking]. If authentication is not used, just omit this option.
    - **`execute`** *(object)*: The startAddress will be the jump-to address. No further processing of SB after jump, ROM do not expect to return.
      - **`address`** *(['string', 'number'])*: Jump-to address to start execute code.
    - **`call`** *(object)*: The startAddress will be the address to jump, however, the state machine should expect a return to the next statement to continue processing the sb file.
      - **`address`** *(['string', 'number'])*: Jump-to address to start execute code.
    - **`programFuses`** *(object)*: The startAddress will be the address of fuse register, length will be number of fuse words to program. The data to write to the fuse registers will immediately follow the header.
      - **`address`** *(['string', 'number'])*: Address of fuses to be burned.
      - **`values`** *(string)*: Binary values delimited by comma to be burned.
    - **`programIFR`** *(object)*: The startAddress will be the address into the IFR region, length will be in number of bytes to write to IFR region. The data to write to IFR region at the given address will immediately follow the header.
      - **`address`** *(['string', 'number'])*: Address of IFR region to be programmed.
      - **`file`** *(string)*: Binary file to be programmed.
    - **`loadCMAC`** *(object)*: If set, then the data to write immediately follows the range header. The length field contains the actual data length. ROM is calculating cmac from loaded data and storing on address known by ROM decided based on startAddress.
      - **`address`** *(['string', 'number'])*: Address of memory block to be CMAC loaded.
      - **`memoryId`** *(['string', 'number'])*: ID of memory block to be CMAC loaded.
      - **`file`** *(string)*: Binary file to be loaded.
    - **`copy`** *(object)*: Used for copying data from one place to another. 32 bytes fixed size.
      - **`addressFrom`** *(['string', 'number'])*: Address of memory block to be copied.
      - **`memoryIdFrom`** *(['string', 'number'])*: ID of memory block to be copied.
      - **`size`** *(['string', 'number'])*: Size of memory block to be copied.
      - **`addressTo`** *(['string', 'number'])*: Address of memory where block to be copied.
      - **`memoryIdTo`** *(['string', 'number'])*: ID of memory block where to be copied.
    - **`loadHashLocking`** *(object)*: If set, then the data to write immediately follows the range header. The length field contains the actual data length. ROM is calculating hash of the data and storing the value in the last 64 bytes of the loaded data, which are reserved for it.
      - **`address`** *(['string', 'number'])*: Address of memory block to be loaded.
      - **`memoryId`** *(['string', 'number'])*: ID of memory block to be loaded.
      - **`file`** *(string)*: Binary file to be loaded.
    - **`loadKeyBlob`** *(object)*: Wrapped key blob immediately follows the range key blob header. The length field contains the actual data length.
      - **`offset`** *(['string', 'number'])*: Offset of the key blob.
      - **`wrappingKeyId`** *(string)*: Wrapping ID of key blob. Must be one of: `['NXP_CUST_KEK_INT_SK', 'NXP_CUST_KEK_EXT_SK']`.
      - **`file`** *(string)*: Binary file to be loaded.
    - **`configureMemory`** *(object)*: Configure memory.
      - **`configAddress`** *(['string', 'number'])*: Configuration address.
      - **`memoryId`** *(['string', 'number'])*: ID of memory block to be configured.
    - **`fillMemory`** *(object)*: Used for filling of the memory range by same repeated int32 pattern.
      - **`address`** *(['string', 'number'])*: Address of memory block to be filled.
      - **`size`** *(['string', 'number'])*: Size of memory block to be filled.
      - **`pattern`** *(['string', 'number'])*: Pattern which will be used to fill memory.
    - **`checkFwVersion`** *(object)*: Used to execute check of provided counter value with value stored in specified monotonous counter in device. If values are not same, SB file is rejected.
      - **`value`** *(['string', 'number'])*: Firmware version to be compared.
      - **`counterId`** *(string)*: ID of FW counter to be checked. Must be one of: `['none', 'nonsecure', 'secure', 'radio', 'snt', 'bootloader']`.

```yaml
# ===========  YAML template SecureBinary31  ===========
#  
#  == Basic Settings == 
#  
firmwareVersion: 0  # [Optional], Firmware version., Version of application image firmware.
#  
#  == Certificate V3.1 Settings == 
#  
useIsk: false # [Required], Use ISK for signature certification, Enable ISK type of signature certification
signingCertificatePrivateKeyFile: isk_prv_key.pem # [Conditionally required], ISK Certificate private key, ISK Certificate private key used to sign certificate
mainRootCertPrivateKeyFile: main_cert_prv_key.pem # [Conditionally required], Main root Certification Private Key, Path to Main root Certification Private Key
rootCertificateEllipticCurve: secp256r1 # [Optional], Type of elliptic curve of root key., Elliptic curve type used for root key.
iskCertificateEllipticCurve: secp256r1 # [Optional], Type of elliptic curve of ISK key., Elliptic curve type used for ISK key.
signingCertificateFile: sign_cert.pem # [Conditionally required], Signing Certificate, Path to Signing Certificate
signingCertificateConstraint: 0 # [Optional], Signing certificate constrain, Signing certificate constrain number
signCertData: sign_cert.bin # [Optional], Signing Certificate data, Path to Signing Certificate data
#  
#  == Certificate Settings == 
#  
rootCertificate0File: my_certificate0.pem # [Required], Root Certificate File 0, Root certificate file index 0.
rootCertificate1File: my_certificate1.pem # [Optional], Root Certificate File 1, Root certificate file index 1.
rootCertificate2File: my_certificate2.pem # [Optional], Root Certificate File 2, Root certificate file index 2.
rootCertificate3File: my_certificate3.pem # [Optional], Root Certificate File 3, Root certificate file index 3.
mainRootCertId: 0 # [Optional], Main Certificate Index, Index of certificate that is used as a main.
family: lpc55s3x # [Required], MCU family., MCU family name.
#  
#  == Secure Binary v3.1 Settings == 
#  
containerKeyBlobEncryptionKey: my_pck.txt # [Optional], Part Common Key., Path to PCK/NPK key in plain hex string format.
isNxpContainer: false # [Optional], Enable NXP Container format., Internal usage only, used for generating SB files with NXP content e.g. provisioning firmware, sentinel firmware...
description: This is description of my generated SB file. # [Optional], Description., Description up to 16 characters, longer will be truncated by elftosb, stored in SB3.1 manifest. If not provided, inserted elftosb version automatically.
kdkAccessRights: 0 # [Optional], KDK access rights., Accepted values are 0, 1, 2 and 3. Value used as key properties for key derivation process, more details can be in CSSv2 manual.  Once will be development finished, one fixed value will be used and probably not required as user input.
containerConfigurationWord: 0 # [Optional], Container configuration word., Flag value in SB3.1 manifest, not used by silicons with LPC55S3x ROM. Value can be keep 0, or item removed from json file.
#  
#  == Secure Binary v3.1 Commands Settings == 
#  
commands: # [Required], SB3.1 Commands, Secure Binary v3.1 commands block, take this list as a full possible example - Modify it regarding your application
  - erase:  # [Optional], Erase, Performs a flash erase of the given address range. The erase will be rounded up to the sector size.
      address: 0  # [Required], Address, Address of memory block to be erased.
      size: 4096 # [Required], Size, Size of memory block to be erased.
      memoryId: 0 # [Optional], Memory ID, ID of memory block to be erased.
  - load:  # [Optional], Load, If set, then the data to write immediately follows the range header. The length field contains the actual data length
      address: 0  # [Required], Address, Address of memory block to be loaded.
      memoryId: 0 # [Optional], Memory ID, ID of memory block to be loaded.
      file: my_binary.bin # [Optional], Binary file., Binary file to be loaded.
      values: 0x1234, 0x5678, 0, 12345678 # [Optional], Binary values., Binary values delimited by comma to be loaded.
      authentication: cmac # [Optional], Authentication., Type of Image authentication [None, cmac, hashlocking]. If authentication is not used, just omit this option.
  - execute:  # [Optional], Execute, The startAddress will be the jump-to address. No further processing of SB after jump, ROM do not expect to return.
      address: 0  # [Required], Address, Jump-to address to start execute code.
  - call:  # [Optional], Call, The startAddress will be the address to jump, however, the state machine should expect a return to the next statement to continue processing the sb file
      address: 0  # [Required], Address, Jump-to address to start execute code.
  - programFuses:  # [Optional], Program Fuses, The startAddress will be the address of fuse register, length will be number of fuse words to program. The data to write to the fuse registers will immediately follow the header.
      address: 0  # [Required], Address, Address of fuses to be burned.
      values: 0x1234, 0x5678, 0, 12345678 # [Required], Binary values., Binary values delimited by comma to be burned.
  - programIFR:  # [Optional], Program IFR, The startAddress will be the address into the IFR region, length will be in number of bytes to write to IFR region. The data to write to IFR region at the given address will immediately follow the header
      address: 0  # [Required], Address, Address of IFR region to be programmed.
      file: my_binary.bin # [Required], Binary file., Binary file to be programmed.
  - loadCMAC:  # [Optional], Load CMAC, If set, then the data to write immediately follows the range header. The length field contains the actual data length. ROM is calculating cmac from loaded data and storing on address known by ROM decided based on startAddress.
      address: 0  # [Required], Address, Address of memory block to be CMAC loaded.
      memoryId: 0 # [Optional], Memory ID, ID of memory block to be CMAC loaded.
      file: my_cmac_binary.bin # [Required], Binary file., Binary file to be loaded.
  - copy:  # [Optional], Copy, Used for copying data from one place to another. 32 bytes fixed size.
      addressFrom: 0  # [Required], Address From, Address of memory block to be copied.
      memoryIdFrom: 0 # [Optional], Memory ID From, ID of memory block to be copied.
      size: 4096 # [Required], Size, Size of memory block to be copied.
      addressTo: 536870912 # [Required], Address To, Address of memory where block to be copied.
      memoryIdTo: 0 # [Optional], Memory ID To, ID of memory block where to be copied.
  - loadHashLocking:  # [Optional], Load with HASH locking, If set, then the data to write immediately follows the range header. The length field contains the actual data length. ROM is calculating hash of the data and storing the value in the last 64 bytes of the loaded data, which are reserved for it.
      address: 0  # [Required], Address, Address of memory block to be loaded.
      memoryId: 0 # [Optional], Memory ID, ID of memory block to be loaded.
      file: my_hashlocking_binary.bin # [Required], Binary file., Binary file to be loaded.
  - loadKeyBlob:  # [Optional], Load Key Blob, Wrapped key blob immediately follows the range key blob header. The length field contains the actual data length.
      offset: 0  # [Required], Offset, Offset of the key blob.
      wrappingKeyId: 0 # [Required], Wrapping key ID, Wrapping ID of key blob.
      file: my_keyblob.bin # [Required], Binary file., Binary file to be loaded.
  - configureMemory:  # [Optional], Configure memory, Configure memory.
      configAddress: 0  # [Required], Address, Configuration address.
      memoryId: 0 # [Optional], Memory ID, ID of memory block to be configured.
  - fillMemory:  # [Optional], Fill memory, Used for filling of the memory range by same repeated int32 pattern.
      address: 0  # [Required], Address, Address of memory block to be filled.
      size: 4096 # [Required], Size, Size of memory block to be filled.
      pattern: 2779096485 # [Required], Pattern, Pattern which will be used to fill memory.
  - checkFwVersion:  # [Optional], Check firmware version, Used to execute check of provided counter value with value stored in specified monotonous counter in device. If values are not same, SB file is rejected.
      value: 1  # [Required], Value - Firmware version, Firmware version to be compared.
      counterId: secure # [Required], Counter ID, ID of FW counter to be checked.

```
