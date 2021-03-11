using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;

namespace yadaMail
{
    class Program
    {
        static Task<int> Main(string[] args)
        {
            var rootCommand = new RootCommand
            {
                new Option<string>("--host"),
                new Option<int>("--port"),
                new Option<string>("--username"),
                new Option<DirectoryInfo>("--yara")
            };

            rootCommand.Description = "Scan your inbox with Yara rules";

            rootCommand.Handler = CommandHandler.Create<string, int, string, DirectoryInfo>((host,
                port,
                username,
                yara) =>
            {
                var mailScanner = new YadaMail(host, port);
                mailScanner.AddYaraFolder(yara);
                mailScanner.InitializeYara();
                mailScanner.Connect(username);
                mailScanner.Scan(DateTime.Now.AddDays(-7));
            });

            return rootCommand.InvokeAsync(args);
        }
    }
}