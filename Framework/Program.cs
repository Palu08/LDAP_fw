using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Framework.lib2;

namespace Framework
{
    internal class Program
    {
        static Module actual_module = new Module();

        static Dictionary<string, Module> modules_list = new Dictionary<string, Module>() {
                                                 { "RBCD", new Modules.RBCD() },
                                                 { "SAMAS", new Modules.SAMAS() }
                                                 };

        static void ListModules()
        {
            Console.WriteLine("Modules list :\n");
            Console.WriteLine("id  name          desc");
            Console.WriteLine(new String('-', 22));
            int i = 1;
            foreach (var module in modules_list)
            {
                Console.Write(" {0}  ", i);
                Console.ForegroundColor = ConsoleColor.Red; Console.Write("{0}", module.Value.get_name);
                Console.ForegroundColor = ConsoleColor.White; Console.WriteLine(" ===>{1}{0}", module.Value.get_shortDesc, new String(' ', 14 - 5 - module.Value.get_name.Length));
                i++;
            }
            Console.WriteLine();
        }

        static void LoadModuleFromName(string moduleName)
        {
            if (modules_list.ContainsKey(moduleName))
            {
                actual_module = modules_list[moduleName];
                Console.Write("Module");
                Console.ForegroundColor = ConsoleColor.Red; Console.Write(" {0} ", actual_module.get_name);
                Console.ForegroundColor = ConsoleColor.White; Console.WriteLine("loaded !\n");
                return;
            }
            else
            {
                Console.WriteLine("Module {0} not found", moduleName);
            }
        }

        static void LoadModuleFromId(int id)
        {
            if(id>0 && modules_list.Count >= id)
            {
                actual_module = modules_list.ElementAt(id-1).Value;
                Console.Write("Module");
                Console.ForegroundColor = ConsoleColor.Red; Console.Write(" {0} ", actual_module.get_name);
                Console.ForegroundColor = ConsoleColor.White;  Console.WriteLine("loaded !\n");
                return;
            }
            else
            {
                Console.WriteLine("Invalid id used");
                return;
            }
        }

        static void ParseInput(string input)
        {
            string[] inputs = input.Split(' ');
            switch (inputs[0])
            {
                case "use":
                    if (inputs[1].Length == 0)
                    {
                        Console.WriteLine("Please provide a valid module's name or id\n");
                    }
                    else if ("0123456789".Contains(inputs[1][0]))
                    {
                        LoadModuleFromId(Int32.Parse(inputs[1]));
                    }
                    else
                    {
                        LoadModuleFromName(inputs[1]);
                    }
                    break;
                case "scan":
                    if (actual_module.get_name == null)
                    {
                        Console.WriteLine("Please load a module first:\nAvailable commands : list, infos, use, exit\n");
                    }
                    else
                    {
                        actual_module.scan();
                    }
                    break;
                case "run":
                    if (actual_module.get_name == null)
                    {
                        Console.WriteLine("Please load a module first:\nAvailable commands : list, infos, use, exit\n");
                    }
                    else
                    {
                        actual_module.run();
                    }
                    break;
                case "clean":
                    if (actual_module.get_name == null)
                    {
                        Console.WriteLine("Please load a module first:\nAvailable commands : list, infos, use, exit\n");
                    }
                    else
                    {
                        actual_module.clean();
                    }
                    break;
                case "set":
                    if (actual_module.get_name == null)
                    {
                        Console.WriteLine("Please load a module first:\nAvailable commands : list, infos, use, exit\n");
                    }
                    else
                    {
                        if (inputs.Length != 3)
                        {
                            Console.WriteLine("Please provide a valid option set command:");
                            Console.WriteLine("set OPTION_NAME VALUE\n");
                        }
                        else
                        {
                            actual_module.setOption(inputs[1], inputs[2]);
                        }
                    }
                    break;
                case "list":
                    ListModules();
                    break;
                case "info" : case "infos":
                    actual_module.getInfos();
                    break;
                case "exit":
                    Console.WriteLine("Bye !");
                    System.Environment.Exit(0);
                    break;
                default :
                    Console.WriteLine("Unrecognized Command");
                    if (actual_module.get_name == null)
                    {
                        Console.WriteLine("Available commands : list, infos, use, exit\n");
                    }
                    else
                    {
                        Console.WriteLine("Available commands : scan, run, clean, list, infos, use, exit\n");
                    }
                    break;
            }
        }
        
        static void Main(string[] args)
        {
            while (true)
            {
                string display = "(framework)";
                if (actual_module.get_name != null)
                {
                    display += "(" + actual_module.get_name + ")>";
                }
                else
                {
                    display += '>';
                }
                Console.Write(display);
                var input = Console.ReadLine();
                ParseInput(input);
            }
        }
    }
}
