namespace AuthenticationServer.Data.Commands
{
    public class VerifyUserCommand
    {

        public string? UserEmail { get; set; }
        public string? NotificationToken { get; set; }
        public string? Token { get; set; }
        public string? DeviceId { get; set; }
    }
}
