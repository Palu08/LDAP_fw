using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Framework
{
    public class Module
    {
        public struct option
        {
            public string option_name;
            public bool option_mandatory;
            public string option_value;
            public string option_description;
            public option(string name, bool mandatory, string defaut, string description)
            {
                option_name = name;
                option_mandatory = mandatory;
                option_value = defaut;
                option_description = description;
            }

            public void setOption(string value)
            {
                this.option_value = value;
            }
        }

        protected string name = null;
        protected string shortDesc = null;
        protected string desc = "INFOS SUR LE FRAMEWORK";
        protected option[] options = new option[0];

        public virtual string get_shortDesc { get { return shortDesc; } }
        public virtual string get_desc { get { return desc; } }

        public virtual string get_name { get { return name; } }

        public virtual void getInfos()
        {
            if (options.Length == 0)
            {
                Console.WriteLine("Please select a module before calling infos");
                return;
            }
            Console.WriteLine("MODULE : {0}\n", name);
            Console.WriteLine("{0}\n", desc);

            int o_name = 0;
            int o_value = 0;
            int o_desc = 0;

            foreach (option o in options)
            {
                o_name = (o.option_name.Length > o_name) ? o.option_name.Length : o_name;
                o_value = (o.option_value.Length > o_value) ? o.option_value.Length : o_value;
                o_desc = (o.option_description.Length > o_desc) ? o.option_description.Length : o_desc;
            }

            Console.WriteLine(o_name);
            Console.WriteLine(o_desc);
            Console.WriteLine(o_value);

            string _option = "OPTION" + new string(' ', o_name - 3);
            string _required = "REQUIRED   ";
            string _value = "VALUE" + new string(' ', o_value - 2);
            string _desc = "DESCRIPTION";
            string line = _option + "|" + _required + "|" + _value + "|" + _desc;

            Console.WriteLine(line);
            Console.WriteLine(new String('-', line.Length));

            foreach (option o in options) {
                Console.WriteLine(o.option_name + new String(' ', o_name - o.option_name.Length) + '|' +
                                  o.option_mandatory + new string(' ', 11 - (o.option_mandatory ? 4 : 5)) + '|' +
                                  o.option_value + new string(' ', o_value - o.option_value.Length) + '|' +
                                  o.option_description );
            }
            Console.WriteLine("\n");
        }

        public virtual void scan()
        {
            Console.WriteLine("No scan action on this module\n");
        }
        public virtual void run()
        {
            Console.WriteLine("No run action on this module\n");
        }
        public virtual void clean()
        {
            Console.WriteLine("No clean action on this module\n");
        }

        public virtual string getOptions(string optionName)
        {
            foreach (option o in options)
            {
                if (o.option_name == optionName)
                {
                    if (o.option_value == "")
                    {
                        return null;
                    }
                    return o.option_value;
                }
            }
            return null;
        }

        public virtual bool checkOptions()
        {
            foreach (option o in options)
            {
                if (o.option_mandatory && o.option_value == "")
                {
                    Console.WriteLine("Please provide all required options\n");
                    return false;
                }
            }
            return true;
        }

        public virtual void setOption(string optionName, string optionValue)
        {
            bool option_found = false;
            int i = 0;
            foreach (option o in options)
            {
                if (o.option_name == optionName)
                {
                    options[i].option_value = optionValue;
                    Console.ForegroundColor = ConsoleColor.Yellow; Console.Write("[!]");
                    Console.ForegroundColor = ConsoleColor.White; Console.WriteLine("Option {0} set to {1}\n", optionName, (optionValue.Equals(""))?"null":optionValue);
                    option_found = true;
                    break;
                }
                i++;
            }
            if (!option_found)
            {
                Console.WriteLine("Option {0} not found in module {1}\n", optionName, this.name);
            }
        }
    }
}
