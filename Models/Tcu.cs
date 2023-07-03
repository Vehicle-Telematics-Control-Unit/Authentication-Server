using System;
using System.Collections.Generic;

namespace AuthenticationServer.Models;

public partial class Tcu
{
    public string? IpAddress { get; set; }

    public long TcuId { get; set; }

    public string UserId { get; set; } = null!;

    public string Mac { get; set; } = null!;

    public DateTime? ExpiresAt { get; set; }

    public byte[]? Challenge { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public long ModelId { get; set; }

    public virtual ICollection<Alert> Alerts { get; set; } = new List<Alert>();

    public virtual ICollection<ConnectionRequest> ConnectionRequests { get; set; } = new List<ConnectionRequest>();

    public virtual ICollection<DevicesTcu> DevicesTcus { get; set; } = new List<DevicesTcu>();

    public virtual ICollection<LockRequest> LockRequests { get; set; } = new List<LockRequest>();

    public virtual Model Model { get; set; } = null!;

    public virtual ICollection<Tcufeature> Tcufeatures { get; set; } = new List<Tcufeature>();

    public virtual AspNetUser User { get; set; } = null!;
}
