using System.Threading.Tasks;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using HttpClient = System.Net.Http.HttpClient;
using Newtonsoft.Json;
using System.Text;
using Newtonsoft.Json.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Net.Mime;
using System.Text.Json;
using System;

namespace BoApi.Helpers
{
    public class AppleService
    {
        public static async Task<JsonDocument> ValidationMerchent(string filePath)
        {
            // Proceed for an invalid cerficate
            ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) => true;

            System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // Add the certificate
            HttpClientHandler handler = new HttpClientHandler() {
                SslProtocols = SslProtocols.Tls12,
                ClientCertificateOptions = ClientCertificateOption.Manual
            };
            X509Certificate2 cert = LoadCertificateFromDisk(filePath);
            if (cert != null)
            {
                handler.ClientCertificates.Add(cert);
            }

            HttpClient client = new HttpClient(handler, disposeHandler: true);

            var payload = new
            {
                DomainName = Settings.TICKET_ONLINE_HOST,
                DisplayName = Settings.APPLE_PAY_DISPLAY_NAME,
                Initiative = "web",
                MerchantIdentifier = cert,
            };

            var jsonPayload = JsonConvert.SerializeObject(payload);
            using (var content = new StringContent(jsonPayload, Encoding.UTF8, MediaTypeNames.Application.Json))
            {
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                System.Net.ServicePointManager.Expect100Continue = false;
                using (var response = await client.PostAsync(Settings.APPLE_PAY_END_POINT, content))
                {
                    response.EnsureSuccessStatusCode();

                    using (var stream = await response.Content.ReadAsStreamAsync())
                    {
                        return await JsonDocument.ParseAsync(stream);
                    };
                };
            };
        }

        private static X509Certificate2 LoadCertificateFromDisk(string certThumbprint)
        {
            try
            {
                return new X509Certificate2(certThumbprint);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                        $"Could not find Apple Pay merchant certificate with thumbprint My from store Current User in location.");
            }
        }

        private static X509Certificate2 GetCert(string certThumbprint)
        {
            // Load the certificate from the current user's certificate store. This
            // is useful if you do not want to publish the merchant certificate with
            // your application, but it is also required to be able to use an X.509
            // certificate with a private key if the user profile is not available,
            // such as when using IIS hosting in an environment such as Microsoft Azure.
            using (var store = new X509Store(StoreName.AddressBook, StoreLocation.CurrentUser)) {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    certThumbprint,
                    validOnly: false);

                if (certificates.Count < 1)
                {
                    throw new InvalidOperationException(
                        $"Could not find Apple Pay merchant certificate with thumbprint My from store Current User in location '{store.Location}'.");
                }

                return certificates[0];
            };
        }
    }
}
