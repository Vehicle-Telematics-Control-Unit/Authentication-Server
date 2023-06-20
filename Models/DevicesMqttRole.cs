namespace AuthenticationServer.Models;

public partial class DevicesMqttRole
{
    public long RoleId { get; set; }

    public string DeviceId { get; set; } = null!;

    public bool? IsActive { get; set; }

    public virtual Device Device { get; set; } = null!;

    public virtual MqttRole Role { get; set; } = null!;
}
