﻿namespace Interceptor
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using EasyHook;

    public class EntryPoint : IEntryPoint
    {
        private List<LocalHook> hooks;
        private RequestType lastRequestType;
        private SslReadDelegate originalSslRead;
        private SslWriteDelegate originalSslWrite;

        public EntryPoint(RemoteHooking.IContext context, string channelName)
        {
        }

        private enum RequestType
        {
            Unknown,
            Authorize,
            Update,
        }

        public void Run(RemoteHooking.IContext context, string channelName)
        {
#if DEBUG
            WinApi.AllocConsole();
            Debug.Listeners.Add(new TextWriterTraceListener(Console.Out));
#endif

            this.LoadConfiguration();
            this.InstallHooks();
            this.WakeUpProcess();
            this.RunForever();
        }

        private void DebugLogMessage(string message, bool outgoingMessage)
        {
            var debugMessage = new StringBuilder();
            debugMessage.AppendLine("--------------------------------------------------------------------------------");
            debugMessage.AppendLine(outgoingMessage ? "[SEND]" : "[RECV]");
            debugMessage.AppendLine(message);
            debugMessage.AppendLine("--------------------------------------------------------------------------------");
            debugMessage.AppendLine();

            Debug.WriteLine(debugMessage);
        }

        private void InstallHooks()
        {
            var sslReadAddress = LocalHook.GetProcAddress("SSLEAY32", "SSL_read");
            var sslWriteAddress = LocalHook.GetProcAddress("SSLEAY32", "SSL_write");

            this.originalSslRead = Marshal.GetDelegateForFunctionPointer<SslReadDelegate>(sslReadAddress);
            this.originalSslWrite = Marshal.GetDelegateForFunctionPointer<SslWriteDelegate>(sslWriteAddress);

            this.hooks = new List<LocalHook>
            {
                LocalHook.Create(sslReadAddress, new SslReadDelegate(this.SslReadHooked), null),
                LocalHook.Create(sslWriteAddress, new SslWriteDelegate(this.SslWriteHooked), null)
            };

            var excludedThreads = new int[] { };

            // Activate all hooks on all threads
            foreach (var hook in this.hooks)
            {
                hook.ThreadACL.SetExclusiveACL(excludedThreads);
            }
        }

        private void LoadConfiguration()
        {
            // TODO: Load from configuration file
        }

        private void RunForever()
        {
            while (true)
            {
                Thread.Sleep(1000);
            }
        }

        private int SslReadHooked(IntPtr ssl, IntPtr buffer, int length)
        {
            var read = this.originalSslRead(ssl, buffer, length);
            if (read <= 0)
            {
                return read;
            }

            var data = new byte[read];
            Marshal.Copy(buffer, data, 0, read);

            var message = Encoding.ASCII.GetString(data);
            this.DebugLogMessage(message, false);

            if (this.lastRequestType != RequestType.Unknown)
            {
                switch (this.lastRequestType)
                {
                    case RequestType.Authorize:
                        break;

                    case RequestType.Update:
                        // Replace with spoofed response
                        var spoofedResponse = new StringBuilder();
                        spoofedResponse.AppendLine("HTTP/1.1 200 OK");
                        spoofedResponse.AppendLine("Date: Tue, 04 Dec 2018 17:05:41 GMT");
                        spoofedResponse.AppendLine("Content-Type: application/json;charset=utf8");
                        spoofedResponse.AppendLine("Content-Length: 453");
                        spoofedResponse.AppendLine("Connection: keep-alive");
                        spoofedResponse.AppendLine("X-XSS-Protection: 1; mode=block");
                        spoofedResponse.AppendLine("X-frame-options: SAMEORIGIN");
                        spoofedResponse.AppendLine("X-Content-Type-Options: nosniff");
                        spoofedResponse.AppendLine("Server: elb");
                        spoofedResponse.AppendLine("");
                        spoofedResponse.Append("{\"status\":\"0\",\"autoPollingCycle\":\"1\",\"components\":[{\"name\":\"BKL-L09 9.0.0.159(C432E4R1P9)-FULL\",\"version\":\"BKL-L09 9.0.0.159(C432E4R1P9)\",\"versionID\":\"199267\",\"description\":\"\u3010\u5546\u7528\u53D1\u5E03\u3011\u3010\u5168\u91CF\u5305\u3011Berkeley-L09-OTA 9.0.0.159&#40;C432-9.0.0.159&#41;&#40;2018/9/18&#41;-- Google \u8865\u4E01\u6D4B\u8BD5\u7EC4\",\"createTime\":\"2018-11-29T08:19:25+0000\",\"url\":\"http://update.hicloud.com:8180/TDS/data/files/p3/s15/G3536/g1699/v199267/f1/\"}]}");

                        var spoofedResponseData = Encoding.ASCII.GetBytes(spoofedResponse.ToString());
                        Marshal.Copy(spoofedResponseData, 0, buffer, spoofedResponseData.Length);

                        return length;
                }
            }

            return read;
        }

        private int SslWriteHooked(IntPtr ssl, IntPtr buffer, int length)
        {
            var data = new byte[length];
            Marshal.Copy(buffer, data, 0, length);

            var message = Encoding.ASCII.GetString(data);
            this.DebugLogMessage(message, true);

            if (message.Contains("POST /sp_ard_common/v1/authorize.action"))
            {
                this.lastRequestType = RequestType.Authorize;

                // "IMEI" : "XXXXXXXXXXXXXXX",
                const int ImeiValueOffset = 10;
                const int ImeiLength = 15;
                const string SpoofedImei = "501337724238423";

                var imeiParameterIndex = message.IndexOf("\"IMEI\" :");
                var originalImeiValue = message.Substring(imeiParameterIndex + ImeiValueOffset, ImeiLength);

                var spoofedRequest = message.Replace(originalImeiValue, SpoofedImei);

                // Replace with spoofed request
                var spoofedRequestData = Encoding.ASCII.GetBytes(spoofedRequest.ToString());
                Marshal.Copy(spoofedRequestData, 0, buffer, spoofedRequestData.Length);

                this.originalSslWrite(ssl, buffer, spoofedRequestData.Length);
                return length;
            }
            else if (message.Contains("POST /sp_ard_common/v2/Check.action?latest=true"))
            {
                this.lastRequestType = RequestType.Update;
            }
            else
            {
                this.lastRequestType = RequestType.Unknown;
            }

            return this.originalSslWrite(ssl, buffer, length);
        }

        private void WakeUpProcess()
        {
            RemoteHooking.WakeUpProcess();
        }
    }
}