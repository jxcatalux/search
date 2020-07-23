using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.AccountManagement;
using System.Xml.Linq;
using System.Net;
using System.IO;
using System.Web;
using System.Security.Cryptography;
using System.Xml;
using System.Web.Security;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Web.Hosting;

namespace UNameEmailChooser
{
    public class UNameEmailChooser
    {
        static string userName = "";
        static string processLog = "";
        static string logFile = "C:\\SCI\\Logs\\";

        public static void Log(string logMessage, TextWriter w)
        {
            w.Write("\r\nLog Entry : ");
            w.WriteLine($"{DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()}");
            w.WriteLine("  :");
            w.WriteLine($"  :{logMessage}");
            w.WriteLine("-------------------------------");
        }

        public static bool ADUserExists(string userName, string domainName)
        {
            processLog += "Checking if UserID <strong>" + userName + "</strong> exists in Active Directory<br>";
            using (var domainContext = new PrincipalContext(ContextType.Domain, domainName))
            {
                var user = UserPrincipal.FindByIdentity(domainContext, IdentityType.SamAccountName, userName);
                if (user != null)
                {
                    processLog += "Yes, the user <strong>" + userName + "</strong> already exists in Active Directory<br>";
                    processLog += "Will try a different username<br>";
                    return true;
                }
                else
                {
                    processLog += "No, the user <strong>" + userName + "</strong> does not exist in Active Directory<br>";
                    processLog += "Will continue with this username<br>";
                    return false;
                }
            }
        }

        public static bool SAPUserExists(string userName, string lastName, string endPoint, string webMethodUname, string webMethodPassword, string soapActionGet, string sapNamespaceUrl, string wssPasswordType)
        {
            processLog += "Creating an object/instance of the UNameEmailChooserWebService class<br>";
            UNameEmailChooserWebService saws = new UNameEmailChooserWebService(endPoint, "sapUserGet", webMethodUname, webMethodPassword, soapActionGet, sapNamespaceUrl, wssPasswordType);
            saws.Params.Add("i_userName", userName);
            processLog += "Calling the web service to check if UserID <strong>" + userName + "</strong> exists in SAP<br>";
            saws.Invoke();
            string myresultString = saws.ResultString;
            XDocument myresultXml = saws.ResultXML;
            string o_returnMessage = "";
            var nodesCollection = from nodes in myresultXml.DescendantNodes() select nodes;
            foreach (var nodeVar in nodesCollection)
            {
                XNode node = (XNode)nodeVar;
                if (node.NodeType == XmlNodeType.Text && node.Parent.Name == "o_returnMessage")
                {
                    o_returnMessage = node.ToString();
                    break;
                }
            }
            if (string.IsNullOrEmpty(o_returnMessage))
            {
                throw new Exception("The SAP account web service returned a result that this process does not expect or understand");
            }
            else if (o_returnMessage == "0")
            {
                processLog += "No, the user <strong>" + userName + "</strong> does not exist in SAP<br>";
                processLog += "Will continue with this username<br>";
                return false;
            }
            else if (o_returnMessage == "1")
            {
                processLog += "Yes, the user <strong>" + userName + "</strong> already exists in SAP<br>";
                processLog += "Will try a different username<br>";
                return true;
            }
            else
            {
                throw new Exception("The SAP account web service returned a result that this process does not expect or understand. Return Message: " + o_returnMessage);
            }
        }

        public static string ChooseADOrSAPUserName(string firstName,
            string lastName,
            string domainName,
            string endPoint,
            string webMethodUname,
            string webMethodPassword,
            string soapActionGet,
            string sapNamespaceUrl,
            string wssPasswordType)
        {
            try
            {
                if (!Directory.Exists(logFile))
                {
                    logFile = "C:\\";
                }

                logFile += "UNameEmailChooserLog_" + DateTime.Today.Year.ToString() + string.Format("{0,2:D2}", DateTime.Today.Month) + string.Format("{0,2:D2}", DateTime.Today.Day) + ".txt";

                string logInfo = "First Name -- " + firstName + "\r\nLast Name -- " + lastName + "\r\nDomain  -- " + domainName + "\r\nEndPoint -- " + endPoint + "\r\nwssPasswordType -- " + wssPasswordType;
                logInfo += "webMethodUname -- " + webMethodUname + "\r\nwebMethodPassword -- " + webMethodPassword + "\r\nsoapActionGet  -- " + soapActionGet + "\r\nsapNamespaceUrl -- " + sapNamespaceUrl;
                //debug
                using (StreamWriter w = File.AppendText(logFile))
                {
                    Log(logInfo, w);

                }
               
                using (HostingEnvironment.Impersonate())
                {
                    char[] firstNameArr = firstName.ToCharArray();
                    bool choiceMade = false;
                    string currentFirstNameInitialChars = "";
                    foreach (char fncharacter in firstNameArr)
                    {
                        currentFirstNameInitialChars = currentFirstNameInitialChars + fncharacter.ToString();
                        userName = currentFirstNameInitialChars + lastName;
                        userName = new string(userName.Take(12).ToArray());
                        if (!ADUserExists(userName, domainName))
                        {
                            if (!SAPUserExists(userName, lastName, endPoint, webMethodUname, webMethodPassword, soapActionGet, sapNamespaceUrl, wssPasswordType))
                            {
                                choiceMade = true;
                                break;
                            }
                        }
                    }
                    if (choiceMade)
                    {
                        return userName;
                    }
                    else
                    {
                        int maxIntegerToAppend = 1;
                        string userNameIntAppended = "";
                        string userNamePreferred = firstNameArr[0].ToString() + lastName;
                        while (!choiceMade && maxIntegerToAppend < 1000) 
                        {
                            userNamePreferred = new string(userNamePreferred.Take(9).ToArray());
                            userNameIntAppended = userNamePreferred + maxIntegerToAppend.ToString("000");
                            if (!ADUserExists(userNameIntAppended, domainName))
                            {
                                if (!SAPUserExists(userNameIntAppended, lastName, endPoint, webMethodUname, webMethodPassword, soapActionGet, sapNamespaceUrl, wssPasswordType))
                                {
                                    choiceMade = true;
                                }
                            }
                            maxIntegerToAppend++;
                        }
                        if (choiceMade)
                        {
                            return userNameIntAppended;
                        }
                        else
                        {
                            processLog += "Could not choose a user account for firstname <strong>" + firstName + "</strong> and lastname <strong>" + lastName + "</strong><br>";
                            processLog += "Will skip this user.<br>";

                            using (StreamWriter w = File.AppendText(logFile))
                            {
                                Log(processLog, w);

                            }

                            return "FAILED";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                using (StreamWriter w = File.AppendText(logFile))
                {
                    Log("FAILED: Stacktrace = " + ex.ToString(), w);

                }
                return "FAILED: Stacktrace = " + ex.ToString();
                
            }


        }
    }

    class UNameEmailChooserWebService
    {
        public string Url { get; set; }
        public string MethodName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string SOAPAction { get; set; }
        public string WSSPasswordType { get; set; }
        public string SAPNamespaceUrl { get; set; }
        public Dictionary<string, string> Params = new Dictionary<string, string>();
        public XDocument ResultXML;
        public string ResultString;

        public UNameEmailChooserWebService()
        {
        }

        public UNameEmailChooserWebService(string url, string methodName, string userName, string password, string soapAction, string sapNamespaceUrl, string wssPasswordType)
        {
            Url = url;
            MethodName = methodName;
            UserName = userName;
            Password = password;
            SOAPAction = soapAction;
            WSSPasswordType = wssPasswordType;
            SAPNamespaceUrl = sapNamespaceUrl;
        }

        /// <summary>
        /// Invokes service
        /// </summary>
        public void Invoke()
        {
            Invoke(true);
        }

        /// <summary>
        /// Invokes service
        /// </summary>
        /// <param name="encode">Added parameters will encode? (default: true)</param>
        public void Invoke(bool encode)
        {
            string phrase = Guid.NewGuid().ToString();
            string tempPhrase = phrase.Replace("-", "");
            tempPhrase = tempPhrase.ToUpper();
            string userNameToken = "UsernameToken-" + tempPhrase;
            DateTime created = DateTime.Now;
            string createdStr = created.ToString("yyyy-MM-ddThh:mm:ss.fffZ");
            SHA1CryptoServiceProvider sha1Hasher = new SHA1CryptoServiceProvider();
            byte[] hashedDataBytes = sha1Hasher.ComputeHash(Encoding.UTF8.GetBytes(phrase));
            string nonce = Convert.ToBase64String(hashedDataBytes);
            string soapStr = "";

            if (WSSPasswordType == "PasswordText")
            {
                soapStr =
                    @"<?xml version=""1.0"" encoding=""utf-8""?>
                    <soap:Envelope xmlns:sap=""";
                soapStr += SAPNamespaceUrl;
                soapStr += @""" xmlns:soap=""http://www.w3.org/2003/05/soap-envelope"">
                        <soap:Header>
                            <wsse:Security soap:mustUnderstand=""true""
                                    xmlns:wsse=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""
                                    xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
                                <wsse:UsernameToken wsu:Id=""";
                soapStr += userNameToken;
                soapStr += @""">
                                <wsse:Username>" + UserName + @"</wsse:Username>
                                <wsse:Password Type=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"">" + Password + @"</wsse:Password>
                                <wsse:Nonce EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"">" + nonce + @"</wsse:Nonce>
                                <wsu:Created>" + createdStr + @"</wsu:Created>
                                </wsse:UsernameToken>
                            </wsse:Security>
                        </soap:Header>
                        <soap:Body>
                        <{0}>
                            {1}
                        </{0}>
                        </soap:Body>
                    </soap:Envelope>";
            }
            else if (WSSPasswordType == "None")
            {
                soapStr =
                    @"<?xml version=""1.0"" encoding=""utf-8""?>
                    <soap:Envelope xmlns:sap=""";
                soapStr += SAPNamespaceUrl;
                soapStr += @""" xmlns:soap=""http://www.w3.org/2003/05/soap-envelope"">
                        <soap:Body>
                        <{0}>
                            {1}
                        </{0}>
                        </soap:Body>
                    </soap:Envelope>";
            }            

            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(Url);
            req.Headers.Add("SOAPAction", SOAPAction);
            req.ContentType = "application/soap+xml;charset=\"utf-8\"";
            req.Accept = "application/soap+xml";
            req.Method = "POST";

            if (WSSPasswordType == "None")
            {
                NetworkCredential netCredential = new NetworkCredential(UserName, Password);
                byte[] credentialBuffer = new UTF8Encoding().GetBytes(UserName + ":" + Password);
                string auth = Convert.ToBase64String(credentialBuffer);
                req.Headers.Add("Authorization", "Basic " + auth);
            }

            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(
                delegate (
                object sender,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors)
            {
                return true;
            });

            using (Stream stm = req.GetRequestStream())
            {
                string postValues = "";
                foreach (var param in Params)
                {
                    if (encode)
                        postValues += string.Format("<{0}>{1}</{0}>", HttpUtility.UrlEncode(param.Key), HttpUtility.UrlEncode(param.Value));
                    else
                        postValues += string.Format("<{0}>{1}</{0}>", param.Key, param.Value);
                }

                soapStr = string.Format(soapStr, MethodName, postValues);
                using (StreamWriter stmw = new StreamWriter(stm))
                {
                    stmw.Write(soapStr);
                }
            }

            using (StreamReader responseReader = new StreamReader(req.GetResponse().GetResponseStream()))
            {
                string result = responseReader.ReadToEnd();
                ResultXML = XDocument.Parse(result);
                ResultString = result;
            }
        }
    }
}
