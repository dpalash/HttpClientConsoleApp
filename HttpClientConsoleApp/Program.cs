using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HttpClientConsoleApp
{
    class Program
    {
        private static bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            if (certificate.GetCertHashString() == "1E52BF71D07CD49E01C5579B9BC25F2535B75CBF")
            {
                return true;
            }

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

        static void Main(string[] args)
        {
            //// Create a TCP/IP client socket. The machineName is the host running the server application.
            string machineName = "127.0.0.1";
            string serverName = "test";
            TcpClient client = new TcpClient(machineName, 443);
            Console.WriteLine("Client connected.");
            // Create an SSL stream that will close the client's stream.
            SslStream sslStream = new SslStream(
                client.GetStream(), false,
                new RemoteCertificateValidationCallback(ValidateRemoteCertificate), null);
            // The server name must match the name on the server certificate.
            try
            {
                sslStream.AuthenticateAsClient(serverName, null, System.Security.Authentication.SslProtocols.Tls | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Ssl2 | System.Security.Authentication.SslProtocols.Ssl3, false);
                //sslStream.AuthenticateAsClient(serverName);

                var outputMessage = "Hello from the client " + Process.GetCurrentProcess().Id.ToString() + ".";
                var outputBuffer = Encoding.UTF8.GetBytes(outputMessage);
                sslStream.Write(outputBuffer);
                Console.WriteLine("Sent: {0}", outputMessage);

                var inputBuffer = new byte[4096];
                var inputBytes = 0;
                while (inputBytes == 0)
                {
                    inputBytes = sslStream.Read(inputBuffer, 0, inputBuffer.Length);
                }
                var inputMessage = Encoding.UTF8.GetString(inputBuffer, 0, inputBytes);
                Console.WriteLine("Received: {0}", inputMessage);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }









            string host = @"https://127.0.0.1:443/packages";
            string certName = Path.Combine(Directory.GetCurrentDirectory(), @"Certificate\SFNeptuneLiveCertificate.pfx");
            string password = "Signed@321";

            try
            {
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                certificates.Import(certName, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Ssl3;
                ServicePointManager.Expect100Continue = false;
                ServicePointManager.CheckCertificateRevocationList = false;
                ServicePointManager.MaxServicePointIdleTime = 10000;

                ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(host);
                //req.AllowAutoRedirect = true;
                req.ContentType = "application/x-www-form-urlencoded";
                req.Timeout = 180000;
                req.KeepAlive = false;
                req.ProtocolVersion = HttpVersion.Version11;
                req.ClientCertificates = certificates;
                req.Headers.Set("EOF", "<EOF>");
                req.Method = "POST";
                req.MediaType = "HTTP/1.1";
                req.UserAgent = "Example Client";
                req.ContentType = "application/x-www-form-urlencoded";
                string postData = "this is the demo post data from client";
                byte[] postBytes = Encoding.UTF8.GetBytes(postData);
                req.ContentLength = postBytes.Length;

                Stream postStream = req.GetRequestStream();
                postStream.Write(postBytes, 0, postBytes.Length);
                postStream.Flush();
                postStream.Close();

                WebResponse resp = req.GetResponse();
                Stream stream = resp.GetResponseStream();
                using (StreamReader reader = new StreamReader(stream))
                {
                    var xxx = reader.ReadToEnd();
                    string line = reader.ReadLine();
                    while (line != null)
                    {
                        Console.WriteLine(line);
                        line = reader.ReadLine();
                    }
                }

                stream.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            Console.ReadKey();

            Download dw = new Download();
            dw.DownloadFile("https://127.0.0.1:8085/Afternoon", @"E:\Temp\abc.exe");
            //dw.DownloadFile("https://127.0.0.1:8085/palash", @"E:\Temp\abc.exe");



            //WebRequestHandler handler = new WebRequestHandler();
            //X509Certificate2 certificate = GetMyX509Certificate(@"F:\Data\Certificates\SFNeptuneLiveCertificate.pfx");
            //handler.ClientCertificates.Add(certificate);
            //using (HttpClient httpClient = new HttpClient(handler))
            //{
            //    System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;
            //    ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            //    httpClient.BaseAddress = new Uri("http://127.0.0.1:8085/"); //Neptune Server HTTP Port
            //    //httpClient.BaseAddress = new Uri("http://127.0.0.1:8083/");
            //    //httpClient.BaseAddress = new Uri("https://127.0.0.1:8084/");

            //    //httpClient.BaseAddress = new Uri("https://127.0.0.1:8085/"); //Neptune Server HTTP Port with SSL Certificate Attached with the 8085 port

            //    httpClient.DefaultRequestHeaders.Accept.Clear();
            //    //httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));

            //    var byteArray = Encoding.ASCII.GetBytes("PALASH:PALASH@123");

            //    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            //    using (HttpResponseMessage response = httpClient.GetAsync("packages").Result)
            //    {
            //        using (Stream streamToReadFrom = response.Content.ReadAsStreamAsync().Result)
            //        {
            //        }
            //    }

            //    using (HttpResponseMessage response = httpClient.GetAsync("packages", HttpCompletionOption.ResponseHeadersRead).Result)
            //    {
            //        using (Stream streamToReadFrom = response.Content.ReadAsStreamAsync().Result)
            //        {
            //            string fileToWriteTo = Path.GetTempFileName();
            //            using (Stream streamToWriteTo = File.Open(fileToWriteTo, FileMode.Create))
            //            {
            //                streamToReadFrom.CopyToAsync(streamToWriteTo).Wait();
            //            }
            //        }
            //    }

            //}

            Console.ReadKey();
        }

        private static X509Certificate2 GetMyX509Certificate(string fileNameWithPath)
        {
            X509Certificate2 x509 = new X509Certificate2();
            //Create X509Certificate2 object from .cer file.
            byte[] rawData = ReadFile(fileNameWithPath);

            x509.Import(rawData, "Signed@321", X509KeyStorageFlags.DefaultKeySet);
            return x509;
        }

        //Reads a file.
        internal static byte[] ReadFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }











        public class Download
        {
            public event EventHandler<DownloadStatusChangedEventArgs> DownloadStatusChanged;
            public event EventHandler<DownloadProgressChangedEventArgs> DownloadProgressChanged;
            public event EventHandler DownloadCompleted;

            public bool stop = true; // by default stop is true
            private string _XmlChunkIn;
            private char[] _XmlChunkOut;

            public void DownloadFile(string DownloadLink, string downloadFilePath)
            {
                stop = false; // always set this bool to false, everytime this method is called

                long ExistingLength = 0;
                FileStream saveFileStream;

                if (File.Exists(downloadFilePath))
                {
                    FileInfo fileInfo = new FileInfo(downloadFilePath);
                    ExistingLength = fileInfo.Length;
                }

                if (ExistingLength > 0)
                {
                    saveFileStream = new FileStream(downloadFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                }
                else
                {
                    saveFileStream = new FileStream(downloadFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                }

                string host = @"https://127.0.0.1:8085/";
                string certName = Path.Combine(Directory.GetCurrentDirectory(), @"Certificate\SFNeptuneLiveCertificate.pfx");
                string password = "Signed@321";

                try
                {
                    X509Certificate2Collection certificates = new X509Certificate2Collection();
                    certificates.Import(certName, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;
                    ServicePointManager.Expect100Continue = false;
                    ServicePointManager.CheckCertificateRevocationList = true;
                    ServicePointManager.MaxServicePointIdleTime = 10000;

                    //ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
                    HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(host);
                    httpWebRequest.AllowAutoRedirect = true;
                    httpWebRequest.ProtocolVersion = HttpVersion.Version10;
                    httpWebRequest.ClientCertificates = certificates;
                    httpWebRequest.Headers.Set("EOF", "<EOF>");
                    httpWebRequest.Method = "POST";
                    httpWebRequest.UserAgent = "Example Client";
                    httpWebRequest.ContentType = "application/x-www-form-urlencoded";
                    //String authKey = "AuthKey";
                    //String authValue = "9e63da82eacac32ae1389dd1a2d36ad7088c37e3665590625ccec43eae5d1d29b706835de79a2b4e80506f582af3676a3a93aa8730a478defab8500d3322c411";
                    //String encoded = System.Convert.ToBase64String(System.Text.Encoding.GetEncoding("ISO-8859-1").GetBytes(authKey + ":" + authValue));
                    //httpWebRequest.Headers.Add("Authorization", "Basic " + encoded);
                    ////Get the headers associated with the request.
                    //WebHeaderCollection myWebHeaderCollection = httpWebRequest.Headers;
                    ////Add the Accept-Language header (for Danish) in the request.
                    //myWebHeaderCollection.Add("AuthKey:9e63da82eacac32ae1389dd1a2d36ad7088c37e3665590625ccec43eae5d1d29b706835de79a2b4e80506f582af3676a3a93aa8730a478defab8500d3322c411");

                    ////Include English in the Accept-Langauge header. 
                    //myWebHeaderCollection.Add("auth", "en;q=0.8");



                    string postData = "login-form-type=cert";
                    byte[] postBytes = Encoding.UTF8.GetBytes(postData);
                    httpWebRequest.ContentLength = postBytes.Length;

                    Stream postStream = httpWebRequest.GetRequestStream();
                    postStream.Write(postBytes, 0, postBytes.Length);
                    postStream.Flush();
                    postStream.Close();

                    WebResponse resp = httpWebRequest.GetResponse();
                    var stream = resp.GetResponseStream();
                    long FileSize = ExistingLength + resp.ContentLength; //response.ContentLength gives me the size that is remaining to be downloaded
                    bool downloadResumable = true; // need it for sending empty progress

                    byte[] downBuffer = new byte[4096];
                    int byteSize = 0;
                    long totalReceived = byteSize + ExistingLength;
                    var sw = new Stopwatch();
                    sw.Start();
                    while ((byteSize = stream.Read(downBuffer, 0, downBuffer.Length)) > 0)
                    {
                        saveFileStream.Write(downBuffer, 0, byteSize);
                        totalReceived += byteSize;

                        var dwargs = new DownloadProgressChangedEventArgs();
                        dwargs.BytesReceived = totalReceived;
                        dwargs.TotalBytesToReceive = FileSize;
                        float currentSpeed = totalReceived / (float)sw.Elapsed.TotalSeconds;
                        dwargs.CurrentSpeed = currentSpeed;
                        if (downloadResumable == true)
                        {
                            dwargs.ProgressPercentage = ((float)totalReceived / (float)FileSize) * 100;
                            long bytesRemainingtoBeReceived = FileSize - totalReceived;
                            dwargs.TimeLeft = (long)(bytesRemainingtoBeReceived / currentSpeed);
                        }
                        else
                        {
                            //args.ProgressPercentage = Unknown;
                            //args.TimeLeft = Unknown;
                        }
                        OnDownloadProgressChanged(dwargs);

                        if (stop == true)
                            return;

                        sw.Stop();
                    }

                    stream.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.ReadKey();




















                X509Certificate2 certificate = GetMyX509Certificate(Path.Combine(Directory.GetCurrentDirectory(), @"Certificate\SFNeptuneLiveCertificate.pfx"));

                var request = (HttpWebRequest)HttpWebRequest.Create(DownloadLink);
                request.ClientCertificates.Add(certificate);
                //request.Proxy = new WebProxy("127.0.0.1", 10494);
                //request.AddRange(ExistingLength);

                //request.KeepAlive = false;
                //request.ProtocolVersion = HttpVersion.Version10;
                //request.ServicePoint.ConnectionLimit = 1;

                //request.ContinueTimeout = 400000;
                //request.Credentials = CredentialCache.DefaultCredentials;
                //request.Credentials = new NetworkCredential("PAALSH", "PALASH@123");

                //request.PreAuthenticate = true;
                //request.ContentType = "text/xml";
                request.Method = "GET";
                //request.Method = "POST";
                //request.Headers.Add("Translate", "t");
                //request.Headers.Set("Pragma", "no-cache");
                request.Headers.Set("EOF", "<EOF>");
                request.MediaType = "HTTP/1.1";
                //request.UserAgent = "Example Client";

                ////Defined data for the Web-Request
                //byte[] byteArrayData = Encoding.ASCII.GetBytes("A string you would like to send by PALASH CLIENT");
                //request.ContentLength = byteArrayData.Length;

                ////Attach data to the Web-Request
                //Stream dataStream = request.GetRequestStream();
                //dataStream.Write(byteArrayData, 0, byteArrayData.Length);
                //dataStream.Close();

                System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;
                System.Net.ServicePointManager.Expect100Continue = false;
                //ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
                request.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateRemoteCertificate);

                //using (Stream dataStream = request.GetRequestStream())
                //{
                //    dataStream.Write(byteArrayData, 0, byteArrayData.Length);
                //    dataStream.Close();
                //}
                try
                {
                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        long FileSize = ExistingLength + response.ContentLength; //response.ContentLength gives me the size that is remaining to be downloaded
                        bool downloadResumable; // need it for sending empty progress

                        if ((int)response.StatusCode == 206)
                        {
                            //Console.WriteLine("Resumable");
                            var downloadStatusArgs = new DownloadStatusChangedEventArgs();
                            downloadResumable = true;
                            downloadStatusArgs.ResumeSupported = downloadResumable;
                            OnDownloadStatusChanged(downloadStatusArgs);
                        }
                        else // sometimes a server that supports partial content will lose its ability to send partial content(weird behavior) and thus the download will lose its resumability
                        {
                            //Console.WriteLine("Resume Not Supported");
                            ExistingLength = 0;
                            var downloadStatusArgs = new DownloadStatusChangedEventArgs();
                            downloadResumable = false;
                            downloadStatusArgs.ResumeSupported = downloadResumable;
                            OnDownloadStatusChanged(downloadStatusArgs);
                            // restart downloading the file from the beginning because it isn't resumable
                            // if this isn't done, the method downloads the file from the beginning and starts writing it after the previously half downloaded file, thus increasing the filesize and corrupting the downloaded file
                            saveFileStream.Dispose(); // dispose object to free it for the next operation
                            File.WriteAllText(downloadFilePath, string.Empty); // clear the contents of the half downloaded file that can't be resumed
                            saveFileStream = new FileStream(downloadFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite); // reopen it for writing
                        }

                        using (var stream = response.GetResponseStream())
                        {
                            byte[] downBuffer = new byte[4096];
                            int byteSize = 0;
                            long totalReceived = byteSize + ExistingLength;
                            var sw = new Stopwatch();
                            sw.Start();
                            while ((byteSize = stream.Read(downBuffer, 0, downBuffer.Length)) > 0)
                            {
                                saveFileStream.Write(downBuffer, 0, byteSize);
                                totalReceived += byteSize;

                                var args = new DownloadProgressChangedEventArgs();
                                args.BytesReceived = totalReceived;
                                args.TotalBytesToReceive = FileSize;
                                float currentSpeed = totalReceived / (float)sw.Elapsed.TotalSeconds;
                                args.CurrentSpeed = currentSpeed;
                                if (downloadResumable == true)
                                {
                                    args.ProgressPercentage = ((float)totalReceived / (float)FileSize) * 100;
                                    long bytesRemainingtoBeReceived = FileSize - totalReceived;
                                    args.TimeLeft = (long)(bytesRemainingtoBeReceived / currentSpeed);
                                }
                                else
                                {
                                    //args.ProgressPercentage = Unknown;
                                    //args.TimeLeft = Unknown;
                                }
                                OnDownloadProgressChanged(args);

                                if (stop == true)
                                    return;
                            }
                            sw.Stop();
                        }
                    }
                    var completedArgs = new EventArgs();
                    OnDownloadCompleted(completedArgs);
                }
                catch (WebException e)
                {
                    string filename = System.IO.Path.GetFileName(downloadFilePath);
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    saveFileStream.Dispose();
                }
            }

            private bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                    return true;

                if (certificate.GetCertHashString() == "1E52BF71D07CD49E01C5579B9BC25F2535B75CBF")
                {
                    return true;
                }

                // Do not allow this client to communicate with unauthenticated servers.
                return false;
            }


            public void StopDownload()
            {
                stop = true;
            }

            protected virtual void OnDownloadStatusChanged(DownloadStatusChangedEventArgs e)
            {
                EventHandler<DownloadStatusChangedEventArgs> handler = DownloadStatusChanged;
                if (handler != null)
                {
                    handler(this, e);
                }
            }

            protected virtual void OnDownloadProgressChanged(DownloadProgressChangedEventArgs e)
            {
                EventHandler<DownloadProgressChangedEventArgs> handler = DownloadProgressChanged;
                if (handler != null)
                {
                    handler(this, e);
                }
            }

            protected virtual void OnDownloadCompleted(EventArgs e)
            {
                EventHandler handler = DownloadCompleted;
                if (handler != null)
                {
                    handler(this, e);
                }
            }


        }

        public class DownloadStatusChangedEventArgs : EventArgs
        {
            public bool ResumeSupported { get; set; }
        }

        public class DownloadProgressChangedEventArgs : EventArgs
        {
            public long BytesReceived { get; set; }
            public long TotalBytesToReceive { get; set; }
            public float ProgressPercentage { get; set; }
            public float CurrentSpeed { get; set; } // in bytes
            public long TimeLeft { get; set; } // in seconds
        }
    }
}
