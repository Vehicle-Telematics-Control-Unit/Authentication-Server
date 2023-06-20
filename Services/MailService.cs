using AuthenticationServer.Configurations;
using AuthenticationServer.Data;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthenticationServer.Services
{
    public class MailService : IMailService
    {
        private readonly EmailConfiguration _emailConfiguration;
        public MailService(IOptions<EmailConfiguration> emailConfiguration) => _emailConfiguration = emailConfiguration.Value;

        public async Task SendEmail(MailData mailMessage)
        {
            MimeMessage emailMessage = CreateEmailMessage(mailMessage);
            await Send(emailMessage);
        }

        private async Task Send(MimeMessage mailMessage)
        {
            using var client = new SmtpClient();
            await Task.Run(() =>
            {
                client.Connect(_emailConfiguration.SmtpServer, _emailConfiguration.Port, true);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailConfiguration.UserName, _emailConfiguration.Password);
                client.Send(mailMessage);
            }).ContinueWith(previousTask =>
            {
                client.Disconnect(true);
                client.Dispose();
            });
        }

        private MimeMessage CreateEmailMessage(MailData mailMessage)
        {
            MimeMessage emailMessage = new();
            emailMessage.From.Add(new MailboxAddress("VehiclePlus", _emailConfiguration.From));
            emailMessage.To.AddRange(mailMessage.To);
            emailMessage.Subject = mailMessage.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = mailMessage.Content };
            return emailMessage;
        }
    }
}
