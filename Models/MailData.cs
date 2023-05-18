using MimeKit;

namespace AuthenticationServer.Models
{
    public class MailData
    {
        public List<MailboxAddress> To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }

        public MailData(IEnumerable<string> to, string subject, string content) {
            To = new List<MailboxAddress>();
            To.AddRange(to.Select(x=> new MailboxAddress("email",x)));
            Subject = subject;
            Content = content;
        }

      
    }
}
