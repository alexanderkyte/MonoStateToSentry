using System;
using SharpRaven;
using SharpRaven.Data;
using SharpRaven.Utilities;

using System.IO;
using Newtonsoft.Json.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using Mono.Collections.Generic;

using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Net;

namespace UploadToSentry
{
    class Uploader
    {
        CodeCollection codebase;

        public void Upload (string filePath, string os_tag, Dsn url)
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

            // var version_string = Regex.Match(payload["configuration"]["version"].ToString(), @"").Groups;

            var event_id = new JProperty("event_id", "f432134b85314b7bb5ad7af568ee278a");
            var timestamp = new JProperty("timestamp", "\t\"timestamp\": \"2018-08-24T14:52:53.382084Z\",\n");
            var exc_objs = new List<JObject> ();
            var failure_type = "Unhandled Managed Exception";

            var stackTraces = payload["threads"] as JArray;
            if (stackTraces.Count > 1)
                failure_type = "Unhandled Unmanaged Exception";

            var culprit = new JProperty("culprit", failure_type);


            for (int i=0; i < stackTraces.Count; i++){
                var thread_id = stackTraces[i]["native_thread_id"].ToString();
                var managed_frame_name = "";

                var unmanaged_frames = new List<JObject>(); 
                var managed_frames = new List<JObject>();

                var payload_unmanaged_frames = stackTraces[i]["managed_frames"] as JArray;
                for (int fr=0; payload_unmanaged_frames != null && fr < payload_unmanaged_frames.Count; fr++)
                {
                    var fn_filename = new JProperty("filename", "unknown");
                    var module = new JProperty("module", "mono-sgen");
                    var function = new JProperty("function", "");

                    unmanaged_frames.Add(new JObject(fn_filename, function, module));

                }

                var payload_managed_frames = stackTraces[i]["managed_frames"] as JArray;
                for (int fr = 0; payload_managed_frames != null && fr < payload_managed_frames.Count; fr++)
                {
                    var frame = payload_managed_frames [fr] as JObject;
                    if (frame["is_managed"] != null && frame["is_managed"].ToString () == "true")
                    {
                        var guid_val = frame["guid"].ToString ();
                        var token_val = Convert.ToUInt32(frame["token"].ToString (), 16);
                        var offset_val = Convert.ToUInt32(frame["il_offset"].ToString (), 16);

                        var output_frame = codebase.Find (guid_val, token_val, offset_val);

                        var guid  = new JProperty("guid", guid_val);
                        var token =  new JProperty("token", token_val);
                        var il_offset = new JProperty("il_offset", offset_val);

                        output_frame.Add (new JProperty("vars", new JObject(guid, token, il_offset)));

                        managed_frames.Add(output_frame);
                    } else {
                        var native_address = frame["native_address"].ToString ();
                        var unmanaged_name = frame["unmanaged_name"].ToString();

                        var fn_filename = new JProperty("filename", "native");
                        var function = new JProperty("function", string.Format ("Offset {0}", unmanaged_name));
                        var module = new JProperty("module", unmanaged_name);
                        var vars = new JProperty("vars", frame);

                        managed_frames.Add(new JObject(fn_filename, function, module));
                    }
                }

                if (managed_frames.Count > 0) {

                    var managed_st = new JObject(new JProperty("frames", new JArray(managed_frames.ToArray ())));

                    exc_objs.Add(new JObject(
                       new JProperty("module", String.Format ("{0}_managed_frames", thread_id)),
                       new JProperty("type", failure_type),
                       new JProperty("value", managed_frame_name),
                       new JProperty("stacktrace", managed_st)));
                }

                if (unmanaged_frames.Count > 0) {
                    var unmanaged_st = new JObject(new JProperty("frames", new JArray(unmanaged_frames.ToArray())));

                    exc_objs.Add(new JObject(
                        new JProperty("module", String.Format("{0}_unmanaged_frames", thread_id)),
                        new JProperty("type", failure_type),
                        new JProperty("value", managed_frame_name),
                        new JProperty("stacktrace", unmanaged_st)));
                }
            }
           
            var exception = new JProperty("exception", new JArray(exc_objs.ToArray ()));
            // Bake in the whole blob
            var embedded = new JProperty("extra", payload);
            var sentry_message = new JObject (timestamp, event_id, culprit, exception, embedded);

            // sent to url via post?
            Console.WriteLine (sentry_message);

            var request = (HttpWebRequest) WebRequest.Create (url.SentryUri);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.UserAgent = PacketBuilder.UserAgent;

            var header = PacketBuilder.CreateAuthenticationHeader(url);


            Stream dataStream = request.GetRequestStream();

            
               
        }

        class CodeCollection
        {
            Dictionary<Tuple<string, uint>, Collection<SequencePoint>> Lookup;
            Dictionary<Tuple<string, uint>, Tuple<string, string, string>> Types;

            public void Add(string assembly, string klass, string function, string mvid, uint token, Collection<SequencePoint> seqs)
            {
                var key = new Tuple<string, uint>(mvid, token);
                Lookup[key] = seqs;
                Types[key] = new Tuple<string, string, string>(assembly, klass, function);
            }

            public CodeCollection()
            {
                Lookup = new Dictionary<Tuple<string, uint>, Collection<SequencePoint>>();
                Types = new Dictionary<Tuple<string, uint>, Tuple<string, string, string>>();
            }

            public JObject Find (string mvid, uint token, uint goal)
            {
                Console.WriteLine ("Query {0} {1:X} {2:X}", mvid, token, goal);
                Console.ReadLine ();

                var method_idx = new Tuple<string, uint>(mvid, token);
                if (!Lookup.ContainsKey(method_idx))
                    return null;

                var seqs = Lookup[method_idx];

                var accum = new JObject();
                foreach (var seq in seqs)
                {
                    if (goal != seq.Offset)
                        continue;

                    accum.Add (new JProperty("lineno", seq.StartLine));
                    accum.Add (new JProperty("filename", seq.Document.Url));
                    break;
                }

                var typ = Types[method_idx];
                var assembly = typ.Item1;
                var klass = typ.Item2;
                accum.Add (new JProperty("module", String.Format("{0} {1}", assembly, klass)));
                accum.Add (new JProperty("function", typ.Item3));

                return accum;
            }
        }

        public Uploader (string inputFolder)
        {
            string[] assemblies = Directory.GetFiles(inputFolder, "*", SearchOption.AllDirectories);
            Console.WriteLine("Traversing {0} assemblies", assemblies.Length);

            this.codebase = new CodeCollection();

            // AppDomain safe_domain = AppDomain.CreateDomain("SafeDomain");
            foreach (string assembly in assemblies)
            {
                if (assembly.EndsWith(".dll") || assembly.EndsWith(".exe"))
                {
                    // Console.WriteLine("Reading {0}", assembly);
                    var readerParameters = new ReaderParameters { ReadSymbols = true };
                    AssemblyDefinition myLibrary = null;
                    try
                    {
                        myLibrary = AssemblyDefinition.ReadAssembly(assembly, readerParameters);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error parsing assembly {1}: {0}", e.Message, assembly);
                        continue;
                    }

                    string mvid = myLibrary.MainModule.Mvid.ToString().ToUpper();

                    Console.WriteLine("{0} {1}", assembly, mvid);
                    Console.WriteLine("Read {0}", assembly);

                    foreach (var ty in myLibrary.MainModule.Types)
                    {
                        for (int i = 0; i < ty.Methods.Count; i++)
                        {
                            string klass = ty.FullName;
                            string function = ty.Methods[i].FullName;
                            uint token = Convert.ToUInt32(ty.Methods[i].MetadataToken.ToInt32());
                            codebase.Add(assembly, klass, function, mvid, token, ty.Methods[i].DebugInformation.SequencePoints);
                        }
                    }
                }
            }

        }

        


        public static void Main(string[] args)
        {
            var file = args [0];
            var os_tag = args [1];
            var url = args [2];
            var assemblies = args [3];

            var dsn = new Dsn(url);
            var state = new Uploader (assemblies);
            state.Upload (file, os_tag, dsn);
        }
    }
}
