namespace AuthenticationServer.Data.Commands
{
    public class ResendCodeCommand
    {
        public string? Username { get; set; }
        public string? DeviceId { get; set; }
    }
}
