using System;
using SharpRaven;
using SharpRaven.Data;
using System.IO;
using Newtonsoft.Json.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Collections.Generic;

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
            var test_name = "test";

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
                //blob.Contexts.Runtime.Version
                blob.Contexts.Device.Architecture = payload["configuration"]["architecture"].ToString();
                blob.Contexts.OperatingSystem.Name = os_tag;
                // blob.Contexts.App.Identifier = test_name;
                blob.Contexts.Device.Name = ""; // Don't track computer usernames

                blob.Fingerprint.Add(hash);
                blob.Fingerprint.Add(increment);
                ravenClient.Capture (blob);
            }

            var event_id = new JProperty("event_id", "f432134b85314b7bb5ad7af568ee278a");
            //var culprit = new JProperty("culprit", "");
            var timestamp = new JProperty("timestamp", "\t\"timestamp\": \"2018-08-24T14:52:53.382084Z\",\n");
            var exc_objs = new List<JObject> ();
            var failure_type = "Unhandled Managed Exception";

            var stackTraces = payload["threads"] as JArray;
            if (stackTraces.Count > 1)
                failure_type = "Unhandled Unmanaged Exception";

            for (int i=0; i < stackTraces.Count; i++){
                exc_objs.Add(new JObject(
                   new JProperty("module", test_name),
                   new JProperty("type", failure_type),
                   new JProperty("value", ""),
                   new JProperty("culprit", "")));
            }

           
            var exception = new JProperty("exception", new JArray(exc_objs.ToArray));



            //var accum = new JObject(event_id, culprit, timestamp, exception);


            "exception": [{
                "module": "UploadToSentry",
                "stacktrace": {
                    "frames": [{
                        "abs_path": null,
                        "colno": 0,
                        "filename": "/Users/akyte/Projects/UploadToSentry/UploadToSentry/Program.cs",
                        "function": "Upload",
                        "in_app": true,
                        "lineno": 43,
                        "module": "UploadToSentry.Uploader",
                        "post_context": null,
                        "pre_context": null,
                        "context_line": "Void Upload(System.String, System.String, System.String)",
                        "vars": null
                    }]
                },
                "type": "Exception",
                "value": "boop"
            }],

            //        new JProperty("channel",
            //          new JObject(
            //              new JProperty("title", "James Newton-King"),
            //              new JProperty("link", "http://james.newtonking.com"),
            //              new JProperty("description", "James Newton-King's blog."),
            //              new JProperty("item",
            //                  new JArray(
            //                      from p in posts
            //                      orderby p.Title
            //                      select new JObject(
            //                          new JProperty("title", p.Title),
            //                          new JProperty("description", p.Description),
            //                          new JProperty("link", p.Link),
            //                          new JProperty("category",
            //                              new JArray(
            //                                  from c in p.Categories
            //                                  select new JValue(c)))))))));

            //Console.WriteLine(rss.ToString());


            //{
                //"event_id": "fc6d8c0c43fc4630ad850ee518f1b9d0",
                //"culprit": "my.module.function_name",
                //"timestamp": "2011-05-02T17:41:36",
                //"tags": {
                //    "ios_version": "4.0"
                //},
                //"exception": [{
                //    "type": "SyntaxError",
                //    "value": "Wattttt!",
                //    "module": "__builtins__"
                //}]
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
