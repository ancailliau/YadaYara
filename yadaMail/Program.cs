using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;
using Spectre.Console;

namespace yadaMail
{
    class Program
    {
        static Task<int> Main(string[] args)
        {
            var rootCommand = new RootCommand
            {
                new Option<string>("--host", () => ""),
                new Option<int>("--port", () => 993),
                new Option<string>("--username", () => ""),
                new Option<DirectoryInfo>("--yara", () => new DirectoryInfo("./rules"))
            };

            rootCommand.Description = "Scan your inbox with Yara rules";

            rootCommand.Handler = CommandHandler.Create<string, int, string, DirectoryInfo>((host,
                port,
                username,
                yara) =>
            {
                while (string.IsNullOrEmpty(host))
                    host = AnsiConsole.Prompt(new TextPrompt<string>("Host"));
                while (port <= 0)
                    port = AnsiConsole.Prompt(new TextPrompt<int>("Port"));
                
                var mailScanner = new YadaMail(host, port);
                mailScanner.AddYaraFolder(yara);
                mailScanner.InitializeYara();

                while (string.IsNullOrEmpty(username))
                    username = AnsiConsole.Prompt(new TextPrompt<string>("Username"));
                
                var password = AnsiConsole.Prompt(
                    new TextPrompt<string>($"Enter password for {username}")
                        .PromptStyle("red")
                        .Secret());
                
                mailScanner.Connect(username, password);
                mailScanner.Scan(DateTime.Now.AddDays(-7));
            });

            return rootCommand.InvokeAsync(args);
        }
    }
}