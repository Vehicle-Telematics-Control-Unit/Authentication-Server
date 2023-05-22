namespace AuthenticationServer.Models;

public partial class Tcu
{
    public string? IpAddress { get; set; }

    public string Vin { get; set; } = null!;

    public long TcuId { get; set; }

    public long CurrentVersionId { get; set; }

    public string UserId { get; set; } = null!;

    public string Mac { get; set; } = null!;

    public DateTime? ExpiresAt { get; set; }

    public byte[]? Challenge { get; set; }

    public virtual ICollection<Alert> Alerts { get; set; } = new List<Alert>();

    public virtual ICollection<ConnectionRequest> ConnectionRequests { get; set; } = new List<ConnectionRequest>();

    public virtual SoftwareVersion CurrentVersion { get; set; } = null!;

    public virtual ICollection<DevicesTcu> DevicesTcus { get; set; } = new List<DevicesTcu>();

    public virtual ICollection<LockRequest> LockRequests { get; set; } = new List<LockRequest>();

    public virtual AspNetUser User { get; set; } = null!;
}
