using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;

namespace Framework.lib2
{
    internal class ADAct
    {
        private string domain;
        private string username;
        private string password;
        private DirectoryEntry rootEntry;
        private PrincipalContext context;

        public ADAct(string domain = null, string username = null, string password = null)
        {
            this.domain = (domain == null) ? Domain.GetCurrentDomain().Name : domain;
            this.username = username;
            this.password = password;
            if (this.username == null || this.password == null)
            {
                this.rootEntry = new DirectoryEntry("LDAP://" + this.domain);
                this.context = new PrincipalContext(ContextType.Domain, this.domain);
            }
            else
            {
                this.rootEntry = new DirectoryEntry("LDAP://" + this.domain, this.username, this.password);
                this.context = new PrincipalContext(ContextType.Domain, this.domain, this.username, this.password);
            }
        }

        public bool RemoveMachineOnDomain(string name)
        {
            try
            {
                // find the computer in question
                ComputerPrincipal computer = ComputerPrincipal.FindByIdentity(this.context, name);

                // if found - delete it
                if (computer != null)
                {
                    computer.Delete();
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        public bool changeMachineSAM(string name, string sam)
        {
            try
            {
                // find the computer in question
                ComputerPrincipal computer = ComputerPrincipal.FindByIdentity(this.context, name);

                // if found - clear SPN
                if (computer != null)
                {
                    computer.SamAccountName = sam;
                    computer.Save();
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public bool clearMachineSPN(string name)
        {
            try
            {
                // find the computer in question
                ComputerPrincipal computer = ComputerPrincipal.FindByIdentity(this.context, name);

                // if found - clear SPN
                if (computer != null)
                {
                    computer.ServicePrincipalNames.Clear();
                    computer.Save();
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                return false;
            }
        }            

        public bool DisableMachineOnDomain(string name)
        {
            try
            {
                // find the computer in question
                ComputerPrincipal computer = ComputerPrincipal.FindByIdentity(this.context, name);

                // if found - delete it
                if (computer != null)
                {
                    computer.Enabled = false;
                    computer.Save();
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        public bool AddMachineToDomain(string name, string password, string cn, string dc)
        {
            string machineAccount = (name[name.Length - 1].Equals('$')) ?
                name.Substring(0, name.Length - 1) : name;
            string samAccountName = machineAccount + '$';
            string machinePassword = password;
            string domain = this.domain.ToLower();
            string dnsHostname = String.Concat(name, ".", domain);
            string distinguishedName = "CN=" + name + "," + cn;
            string[] servicePrincipalName = { String.Concat("HOST/", dnsHostname),
                                              String.Concat("RestrictedKrbHost/", dnsHostname),
                                              String.Concat("HOST/", machineAccount),
                                              String.Concat("RestrictedKrbHost/", machineAccount) };
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(dc + "." + this.domain, 389);
            LdapConnection connection = new LdapConnection(identifier);
            NetworkCredential creds = (this.username != null || this.password != null) ?
                new NetworkCredential(this.username, this.password, this.domain) : null;
            connection = (creds == null) ? new LdapConnection(identifier) : new LdapConnection(identifier, creds);
            try
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
                AddRequest request = new AddRequest();
                request.DistinguishedName = distinguishedName;
                request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                request.Attributes.Add(new DirectoryAttribute("sAMAccountName", samAccountName));
                request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                request.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                request.Attributes.Add(new DirectoryAttribute("servicePrincipalName", servicePrincipalName));
                byte[] unicodePwd = Encoding.Unicode.GetBytes(String.Concat('"', machinePassword, '"'));
                request.Attributes.Add(new DirectoryAttribute("unicodePwd", unicodePwd));
                connection.SendRequest(request);
                connection.Dispose();
                return true;

            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red; Console.Write("[-]");
                if (ex.Message.Contains("The object exists."))
                {
                    Console.ForegroundColor = ConsoleColor.White; Console.WriteLine(" Machine account {0} already exists", machineAccount);
                }
                else if (ex.Message.Contains("The server cannot handle directory requests."))
                {
                    Console.ForegroundColor = ConsoleColor.White; Console.WriteLine(" User may have reached ms-DS-MachineAccountQuota limit\n");
                }

                Console.WriteLine(ex.ToString());
                connection.Dispose();
                return false;
            }
        }
    }
}
