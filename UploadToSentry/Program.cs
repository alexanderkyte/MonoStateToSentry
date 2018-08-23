using System;
using SharpRaven;
using SharpRaven.Data;
using System.IO;
using Newtonsoft.Json.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace UploadToSentry
{
    class Uploader
    {
        public static void Upload (string filePath, string os_tag, string url)
        {
            if (!File.Exists(filePath))
                throw new Exception(String.Format("Json file not found {0}", filePath));

            var dump = File.ReadAllText(filePath);
            var message = new SentryMessage(dump);
            // var blob = new SentryEvent(message);
            var payload = JObject.Parse(dump);

            // Try to extract a test name
            var fileName = Path.GetFileName (filePath);
            var groups = Regex.Match(fileName, @"mono_crash.(\d+).(\d+).json").Groups;
            var hash = groups[1].Value;
            var increment = groups[2].Value;

            var version_string = Regex.Match(payload["configuration"]["version"].ToString(), @"").Groups;


            var ravenClient = new RavenClient(url);
            ravenClient.BeforeSend = requester =>
            {
                Console.WriteLine(requester.Packet.ToString ());
                // Here you can log data from the requester
                // or replace it entirely if you want.
                return requester;
            };

            //ravenClient.Capture(blob);
            try {
                throw new Exception ("boop");
            }
            catch (Exception exc) {
                var blob = new SentryEvent(exc);
                // blob.Contexts.Runtime.RawDescription = );
                blob.Contexts.Device.Architecture = payload["configuration"]["architecture"].ToString();
                blob.Contexts.OperatingSystem.Name = os_tag;
                // blob.Contexts.App.Identifier = test_name;
                blob.Contexts.Device.Name = ""; // Don't track computer usernames

                blob.Fingerprint.Add(hash);
                blob.Fingerprint.Add(increment);
                ravenClient.Capture (blob);
            }
        }

        public static void Main(string[] args)
        {
            var file = args [0];
            var os_tag = args [1];
            var url = args [2];

            Uploader.Upload (file, os_tag, url);
        }
    }
}
