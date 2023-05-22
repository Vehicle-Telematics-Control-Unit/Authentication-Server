namespace AuthenticationServer.Models;

public partial class Device
{
    public string DeviceId { get; set; } = null!;

    public string UserId { get; set; } = null!;

    public DateTime? LastLoginTime { get; set; }

    public string? IpAddress { get; set; }

    public virtual ICollection<ConnectionRequest> ConnectionRequests { get; set; } = new List<ConnectionRequest>();

    public virtual ICollection<DevicesTcu> DevicesTcus { get; set; } = new List<DevicesTcu>();

    public virtual ICollection<LockRequest> LockRequests { get; set; } = new List<LockRequest>();

    public virtual AspNetUser User { get; set; } = null!;
}
