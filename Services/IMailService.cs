using AuthenticationServer.Models;

namespace AuthenticationServer.Services
{
    public interface IMailService
    {
        Task SendEmail(MailData mailMessage);
    }
}
