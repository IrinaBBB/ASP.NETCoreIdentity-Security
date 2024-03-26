using Mailjet.Client;
using Mailjet.Client.Resources;
using System;
using Newtonsoft.Json.Linq;

namespace IdentityNetCore.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        IConfigurationRoot _config;
        public string MailJetAPIKey { get; set; }
        public string MailJetSecretKey { get; set; }
         

        public MailJetEmailSender()
        {
            _config = new ConfigurationBuilder().AddUserSecrets<Program>().Build();
            MailJetAPIKey = _config["MailJetAPIKey"];
            MailJetSecretKey = _config["MailJetSecretKey"];
        }

        public async Task SendEmailAsync(string fromAddress, string toAddress, string subject, string message)
        {
            MailjetClient client = new MailjetClient(MailJetAPIKey, MailJetSecretKey)
            {
                Version = ApiVersion.V3_1
            };

            MailjetRequest request = new MailjetRequest
            {
                Resource = Send.Resource,
            }
            .Property(Send.Messages, new JArray {
                new JObject {
                    { "From", new JObject {
                        { "Email", "balkarovairina@gmail.com" },
                        { "Name", "Irina" }
                    }},
                    { "To", new JArray {
                        new JObject {
                            { "Email", toAddress },
                            { "Name", "" }
                        }
                    }},
                    { "Subject", subject },
                    { "TextPart", message },
                }
            });
            MailjetResponse response = await client.PostAsync(request);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine(string.Format("Total: {0}, Count: {1}\n", response.GetTotal(), response.GetCount()));
                Console.WriteLine(response.GetData());
            } else
            {
                Console.WriteLine(string.Format("StatusCode: {0}\n", response.StatusCode));
                Console.WriteLine(string.Format("ErrorInfo: {0}\n", response.GetErrorInfo()));
                Console.WriteLine(response.GetData());
                Console.WriteLine(string.Format("ErrorMessage: {0}\n", response.GetErrorMessage()));
            }
        }
    }
}
