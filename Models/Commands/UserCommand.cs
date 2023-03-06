namespace AuthenticationServer.Models.Commands
{
    public class UserCommand
    {
        public string? Username { get; set; }
   
        public string? Password { get; set; }
        public int? DeviceId { get; set; }

    }
}
