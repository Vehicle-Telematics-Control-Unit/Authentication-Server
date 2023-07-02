namespace AuthenticationServer.Data.Commands
{
    public class UserCommand
    {
        public string? Username { get; set; }
        public string? NotificationToken { get; set; }
        public string? Password { get; set; }
        public string? deviceId { get; set; }

    }
}
