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
# Mbi_CrcExtXipLpc55s3x

- **`inputImageFile`** *(string)*: The input application image to by modified to Master Boot Image.
- **`enableTrustZone`** *(boolean)*: If not specified, the Trust zone is disabled.
- **`trustZonePresetFile`** *(string)*: If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
- **`family`** *(string)*: MCU family name. Must be one of: `['lpc55xx', 'lpc55s0x', 'lpc55s1x', 'lpc552x', 'lpc55s2x', 'lpc55s3x', 'lpc55s6x', 'rt5xx', 'rt6xx']`.
- **`firmwareVersion`** *(['number', 'string'])*: Version of application image firmware.

```yaml
# ===========  YAML template Mbi_CrcExtXipLpc55s3x  ===========
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
mainRootCertId: 0 # [Required], Main Certificate Index, Index of certificate that is used as a main.
#  
#  == Trust Zone Settings == 
#  
enableTrustZone: false # [Optional], TrustZone enable option, If not specified, the Trust zone is disabled.
trustZonePresetFile: my_tz_custom.yml # [Optional], TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.

```
# Mbi_PlainExtXipSignedLpc55s3x

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
# ===========  YAML template Mbi_PlainExtXipSignedLpc55s3x  ===========
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
mainRootCertId: 0 # [Required], Main Certificate Index, Index of certificate that is used as a main.
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
