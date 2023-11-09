# Data Protection API (DPAPI) For Impact - Ransomware
Abusing Data Protection API (DPAPI) as a technique to encrypt the File System - Ransomware

### Motivation

Throughout history, we have witnessed an incredible number of Windows functionalities being abused for malicious purposes, such as **BitLocker** being used in the development of Ransomware. This is one of the reasons why the author of this research has devoted time to understanding what other functionalities can be abused at the **impact tactic level**, which, in this case, will be **Data Protection API (DPAPI)**.

##### [LockBit ransomware — What You Need to Know](https://www.kaspersky.com/resource-center/threats/lockbit-ransomware)

DPAPI has been the subject of multiple abuses aimed at extracting and accessing user and application secrets, as evidenced by techniques such as **Credentials from Password Stores (T1555)** and **Credentials from Password Stores: Credentials from Web Browsers (T1555.003)**. While it may appear that an API like DPAPI is less likely to be abused when it comes to the *Impact tactic*, we will see that a malicious actor can develop a *malicious artifact* that abuses this function to encrypt a file system.

##### [Credentials from Password Stores ](https://attack.mitre.org/techniques/T1555/)
##### [Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)

All the research that will be shown below is, to a large extent, grounded in the principles of the **Pyramid of Pain**:

The **Pyramid of Pain** is a conceptual model for the effective use of Cyber Threat Intelligence in threat detection operations, with a particular emphasis on *increasing the cost and/or difficulty of adversary operations* to thwart them.
For this reason, adversaries find themselves in the need or position to develop new procedures and techniques, in other words, they constantly need to reinvent themselves.

![blog-pyramid-pain-01-1024x576](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/6ea4fb61-61e0-4e8c-9ac3-4dd865b835e5)

##### [Image retrieved from AttackIQ - What is the Pyramid of Pain?](https://www.attackiq.com/glossary/pyramid-of-pain/)

### DPAPI Explained

Since Windows 2000, Microsoft has equipped its operating systems with a new interface called the **Data Protection Application Programming Interface (DPAPI)** in order to protect all types of information. Within the operating system, we can observe the use of **DPAPI** in the *Windows Credential Manager*, *Windows Vault*, and the *storage of wireless connection passwords*.

DPAPI has become very popular among developers due to its simplicity, as it only requires calling the **Win32 API functions** *CryptProtectData* and *CryptUnprotectData* from the *Crypt32.dll* library to encrypt and decrypt, respectively.


![dpapi1](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/cd83524b-8cff-440c-9df6-ff0d1584ba1c)

##### [Image retrieved from passcape - DPAPI Secrets](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28)

According to official Microsoft documentation, we can use the *CryptProtectData* API to encrypt a *DATA_BLOB* type structure. Typically, only a user with the same *logon credentials* as the one who encrypted the data can decrypt it. Additionally, encryption and decryption are usually expected to occur on the same computer.

* **CryptProtectData**:

```cp
DPAPI_IMP BOOL CryptProtectData(
  [in]           DATA_BLOB                 *pDataIn,
  [in, optional] LPCWSTR                   szDataDescr,
  [in, optional] DATA_BLOB                 *pOptionalEntropy,
  [in]           PVOID                     pvReserved,
  [in, optional] CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
  [in]           DWORD                     dwFlags,
  [out]          DATA_BLOB                 *pDataOut
);
```

* **DATA_BLOB Structure**:

```cp 
typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE  *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB, CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB, CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB, CERT_NAME_BLOB, CERT_RDN_VALUE_BLOB, *PCERT_NAME_BLOB, *PCERT_RDN_VALUE_BLOB, CERT_BLOB, *PCERT_BLOB, CRL_BLOB, *PCRL_BLOB, DATA_BLOB, *PDATA_BLOB, CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB, CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB, CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB, CRYPT_DER_BLOB, PCRYPT_DER_BLOB, CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;
```
#### [CryptProtectData function (dpapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)


Finally, it is very important to note that The function also adds a **Message Authentication Code (MAC) (keyed integrity check)** to the encrypted data to guard against data tampering.

### DPAPI For Impact Pt.1 - No tracks:

The *dwFlags* parameter is of paramount importance as it allows us to enable very specific functions within DPAPI:

- **CRYPTPROTECT_LOCAL_MACHINE:** When this flag is set, it associates the data encrypted with the current computer instead of with an individual user. Any user on the computer on which *CryptProtectData* is called can use *CryptUnprotectData* to decrypt the data. 
- **CRYPTPROTECT_UI_FORBIDDEN:**  This flag is used for remote situations where presenting a user interface (UI) is not an option. When this flag is set and a UI is specified for either the protect or unprotect operation, the operation fails and GetLastError returns the *ERROR_PASSWORD_RESTRICTION* code. 
- **CRYPTPROTECT_AUDIT:**  This flag generates an audit on protect and unprotect operations. Audit log entries are recorded only if szDataDescr is not NULL and not empty. 

The most interesting flag is *CRYPTPROTECT_AUDIT* as it generates an audit on **protect** and **unprotect** operations:

- **Event ID 4694:** *Protection* of auditable protected data was attempted.
- **Event ID 4695:** *Unprotection* of auditable protected data was attempted.

It is of utmost importance to highlight that, according to Microsoft's official documentation, the aforementioned events will only be generated if the *CRYPTPROTECT_AUDIT* flag is **enabled**.

From the adversary's perspective, if these *Win32 APIs* were to be abused, they will obviously not activate that flag to "minimize" the chances of their operations being detected.

##### [DPAPI Events Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-dpapi-activity)

### DPAPI For Impact Pt.2 - Optional Entropy (pOptionalEntropy):

As previously explained, DPAPI typically uses the user's logon credentials for encryption and decryption operation. However, the latter can change if the *CRYPTPROTECT_LOCAL_MACHINE* flag is specified, as it grants all local machine users the authority to decrypt (unprotect) the data. Consequently, if someone encrypts data with DPAPI (as in the case of ransomware), the victim is likely to recover their data without major issues, **unless additional entropy is specified (pOptionalEntropy)**. 

* **pOptionalEntropy**: 
A pointer to a *DATA_BLOB* structure that contains a password or other additional entropy used to encrypt the data. The *DATA_BLOB* structure used in the encryption phase must also be used in the decryption phase. Please note that this value is never saved or written to the hard disk at any point.

If the user or application provides additional entropy to encrypt the data, it must be used during the decryption phase without exception.

### DPAPI For Impact Pt.3 - Connecting the pieces:

Next, we have a .NET developed proof of concept of the malicious artifact (DPAPI For Impact - Ransomware). 

Essentially, the artifact will establish a connection via a **secure channel (HTTPS)** to a **command and control server** to download the additional entropy **(pOptionalEntropy)** into artifact's memory, which, as we explained, will be the value that minimizes the chances of the victim recovering their information.
Also, it is important to note that the malicious artifact takes the files and encrypts them in chunks without damaging the **MAC (Message Authentication Code)**, this will prevent to corrupt the data being encrypted.

On the other hand, it is possible to enhance the sophistication of the malicious artifact by adding anti-forensic properties, for instance, deleting the key from memory immediately after it has been used for its purpose.

**Note:** This malicious artifact was tested multiple times on a **Windows 11 machine** and successfully managed to evade *Windows Defender*.

* **Files before encryption:**

![image](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/f98176d0-c4e0-44db-80a9-f49cc3819f07)

![image](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/fff0655b-f970-4fc4-9d42-c1c9f85ae43f)

* **Running the artifact:**

![image](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/7fe9486f-bef0-418e-b1a4-f2dea6f47c5d)

* **Files after encryption:**

![image](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/406a5e29-af9c-4824-84c5-e030766e2502)

The only way to recover the data is by providing the right Optional Entropy when calling **CryptUnprotectData**.

### DPAPI For Impact Pt.4 - Encrypted Files Entropy:

A file exhibiting **high entropy** suggests that it is well-encrypted, well-compressed, or comprised of genuinely random data.

As an illustrative example, we will take one of the encrypted PDFs.

* **PDF Entropy before encryption:**

![image](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/fd45fbfd-a534-4f67-8304-40022b9048cd)

* **PDF Entropy after encryption:**

In the following graph, we observe the encrypted PDF entropy **(0.980)**, approaching very close to the point of **maximum entropy (1.0)**, and this value remains nearly constant across the file offsets:

![image](https://github.com/CarlosG13/Data-Protection-API-DPAPI-For-Impact---Ransomware/assets/69405457/5a0871aa-8bed-4c15-9dd6-e73b42af2201)

### Possible Solution:

* **API Hooking:** Through this technique, it is possible to *intercept* the call to **CryptProtectData** and determine the **entropy (pOptionalEntropy)** used to encrypt the files. 
**SpecterOps** has already developed a proof of concept that demonstrates this technique in action, known as **EntropyCapture**.

#### [EntropyCapture: Simple Extraction of DPAPI Optional Entropy by Matt Merrill](https://posts.specterops.io/entropycapture-simple-extraction-of-dpapi-optional-entropy-6885196d54d0)
