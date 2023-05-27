using AuthenticationServer.Data;

namespace AuthenticationServer.Services
{
    public interface IMailService
    {
        Task SendEmail(MailData mailMessage);
    }
}
