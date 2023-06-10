namespace AuthenticationServer.Data.Commands
{
    public class VehicleAccessRequestCommand
    {
        public string? Token { get; set; }
        public long? TcuId { get; set; }
        public string? NotificationToken { get; set; }
        public string? deviceId { get; set; }
    }
}
