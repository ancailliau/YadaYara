using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using dnYara;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MimeKit;
using Spectre.Console;

namespace yadaMail
{
    internal class YadaMail : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private readonly IList<DirectoryInfo> _directories;
        
        private ImapClient _client;
        private CompiledRules _rules;

        public YadaMail(string host, int port)
        {
            _host = host;
            _port = port;
            _directories = new List<DirectoryInfo>();
        }

        public void Connect(string username, string password)
        {
            _client = new ImapClient ();
            _client.Connect (_host, _port, SecureSocketOptions.SslOnConnect);
            _client.Authenticate (username, password);
        }

        private void Disconnect()
        {
            _client.Disconnect(true);
        }

        public void Scan(DateTime deliveredAfter)
        {
            if (_client.GetFolder(SpecialFolder.All) is ImapFolder folder)
            {
                folder.Open(FolderAccess.ReadOnly);
                var uniqueIds = folder.Search(SearchQuery.DeliveredAfter(deliveredAfter));
                var items = MessageSummaryItems.BodyStructure | MessageSummaryItems.All | MessageSummaryItems.UniqueId;
                var messages = folder.Fetch (uniqueIds, items);
                ScanMessages(messages, folder);
            }

            Disconnect();
        }

        private void ScanMessages(IList<IMessageSummary> messages, ImapFolder folder)
        {
            if (_rules != null)
            {
                var scanner = new Scanner();

                foreach (var message in messages)
                {
                    if (message.BodyParts.Any(x => x.IsAttachment))
                    {
                        AnsiConsole.Render(
                            new Markup(
                                $"[yellow]{message.Date:dd-MM-yyyy}[/] {message.NormalizedSubject.EscapeMarkup()}\n"));
                        foreach (var attachment in message.BodyParts.Where(x => x.IsAttachment))
                        {
                            var entity = folder.GetBodyPart (message.UniqueId, attachment);
                            var part = (MimePart) entity;
                            AnsiConsole.Render(new Markup($"[grey]Scanning Attachment {part.FileName}[/]\n"));
                            using var stream = new MemoryStream();
                            part.Content.DecodeTo(stream);
                            ScanAttachment(scanner, stream, part.FileName);
                        }
                    }
                }
            }
        }
        
        public void ScanAttachment(Scanner scanner, Stream stream, string filename)
        {
            List<ScanResult> scanResults = scanner.ScanStream(stream, _rules);

            foreach (ScanResult scanResult in scanResults)
            {
                string id = scanResult.MatchingRule.Identifier;

                if (scanResult.Matches.Count == 1)
                {
                    AnsiConsole.Render(new Markup(
                        $"[red]Match found in '{filename}' for rule '{id}.{scanResult.Matches.First().Key}' [/]\n"));
                }
                else
                {
                    AnsiConsole.Render(new Markup($"[red]Match found in '{filename}' for rule '{id}' [/]\n"));
                    foreach (var vd in scanResult.Matches)
                    {
                        AnsiConsole.Render(new Markup($"[red]   > Rule: '{vd.Key}'[/]\n"));
                    }
                }
            }
        }

        public void InitializeYara()
        {
            AnsiConsole.Render(new Markup("[grey]Initialize Yara[/]\n"));
            var ruleFiles = _directories.SelectMany(x => Directory.GetFiles(x.FullName,
                    "*.yar",
                    SearchOption.AllDirectories))
                .ToArray();
            using var ctx = new YaraContext();
            _rules = null;
            using (var compiler = new Compiler())
            {
                AnsiConsole.Progress()
                    .Start(context =>
                    {
                        var task1 = context.AddTask("[grey]Adding rule files[/]");
                        var task2 = context.AddTask("[grey]Compiling rule files[/]");

                        int imported = 0;
                        foreach (var yara in ruleFiles)
                        {
                            compiler.AddRuleFile(yara);
                            imported++;
                            task1.Increment(imported / (1.0 * ruleFiles.Length));
                        }
                        
                        _rules = compiler.Compile();
                        task2.Increment(100);
                    });
            }
        }

        public void Dispose()
        {
            Disconnect();
            _client?.Dispose();
        }

        public void AddYaraFolder(DirectoryInfo directoryInfo)
        {
            _directories.Add(directoryInfo);
        }
    }
}