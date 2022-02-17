using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;

namespace Framework.lib2
{
    public class ADScan
    {
        private string domain;
        private string username;
        private string password;
        private string domainDN ;
        private DirectoryEntry rootEntry;
        private PrincipalContext context;

        public ADScan(string domain = null, string username = null, string password = null)
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
            foreach(string s in this.domain.Split('.')) {
                this.domainDN += "DC=" + s + ",";
            }
            this.domainDN = this.domainDN.Substring(0, this.domainDN.Length - 1);
        }

        public string getOlderDC()
        {
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
            string oldest = "";
            DateTime dc_restart = new DateTime(2100, 01, 01);
            foreach (SearchResult result in searcher.FindAll())
            {
                DateTime LastLogonTime = NativeMethods.GetStartupTime(result.Properties["name"][0].ToString() + "." + this.domain);
                if (DateTime.Compare(LastLogonTime, dc_restart) < 0)
                {
                    oldest = result.Properties["name"][0].ToString();
                    dc_restart = LastLogonTime;
                }
            }
            return oldest;
        }

        public void getDCExploit(DateTime date, string name)
        {
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
            foreach (SearchResult result in searcher.FindAll())
            {
                Console.WriteLine("{");
                var Name = result.Properties["name"][0].ToString();
                var SamAccountName = result.Properties["samAccountName"][0].ToString();
                DateTime LastLogonTime = NativeMethods.GetStartupTime(Name + "." + this.domain);
                String IsVulnerable = (DateTime.Compare(LastLogonTime, date) > 0) ? "Might not be vulnerable to " + name : "Might be vulnerable to " + name;
                if (DateTime.Compare(LastLogonTime, date) > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("\t[-]");
                }
                else 
                {
                    Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine("\t[+]");
                }
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\tName : " + Name);
                Console.WriteLine("\tSamAccountName : " + SamAccountName);
                Console.WriteLine("\tLastLogon : " + LastLogonTime);
                Console.WriteLine("\tVulnerable : " + IsVulnerable);
                Console.WriteLine("}\n");
            }
        }

        public string GetDomainWellKnownObject(string wko)
        {
            // "LDAP://<WKGUID=<Well-Known GUID>,<Domain DN>>"
            DirectoryEntry _rootEntry;
            if (this.username == null || this.password == null)
            {
                _rootEntry = new DirectoryEntry("LDAP://<WKGUID=" + wko + "," + this.domainDN + ">");
            }
            else
            {
                _rootEntry = new DirectoryEntry("LDAP://<WKGUID=" + wko + "," + this.domainDN + ">", this.username, this.password);
            }
            DirectorySearcher searcher = new DirectorySearcher(_rootEntry);
            return searcher.FindAll()[0].Properties["distinguishedName"][0].ToString();
        }

        public string GetDomainAttribute(string attribute)
        {
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(" + attribute + "=*)";
            try
            {
                SearchResultCollection oObject = searcher.FindAll();
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        string attributeResult = omProps[attribute][0].ToString();
                        return attributeResult;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        return "";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return "";
            }
            return "";
        }

        public bool CheckMachineOnBehalf(string machine)
        {
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectClass=computer)(|(SAMAccountName=" + machine +"$)))";
            foreach (SearchResult result in searcher.FindAll())
            {
                foreach (string k in result.Properties.PropertyNames)
                {
                    if (k.Equals("msds-allowedtoactonbehalfofotheridentity"))
                    {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        public byte[] getMachineOnBehalf(string machine)
        {
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectClass=computer)(|(SAMAccountName=" + machine + "$)))";
            try
            {
                foreach (SearchResult result in searcher.FindAll())
                {
                    DirectoryEntry computer = result.GetDirectoryEntry();
                    return (byte[]) computer.Properties["msds-allowedtoactonbehalfofotheridentity"].Value;
                }
                return null;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public bool computerExists(string machine)
        {
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            searcher.Filter = "(&(objectClass=computer)(|(SAMAccountName=" + machine + "$)))";
            if (searcher.FindAll().Count > 0)
            {
                return true;
            }
            return false;
        }

        public string getMachineSID(string name)
        {
            string machine_sid = "";
            DirectorySearcher searcher = new DirectorySearcher(this.rootEntry);
            Console.WriteLine("Checking target computer " + name + " SID...\n");
            searcher.Filter = "(&(objectClass=computer)(|(SAMAccountName=" + name + "$)))";
            foreach (SearchResult result in searcher.FindAll())
            {
                var sid = new SecurityIdentifier((byte[])result.Properties["objectsid"][0], 0);
                Console.WriteLine("SID : " + sid.ToString());
                machine_sid = sid.ToString();
            }
            return machine_sid;
        }
    }
}
