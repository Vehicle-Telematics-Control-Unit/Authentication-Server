namespace AuthenticationServer.Models;

public partial class TcuMqttRole
{
    public long RoleId { get; set; }

    public long TcuId { get; set; }

    public bool? IsActive { get; set; }

    public virtual MqttRole Role { get; set; } = null!;

    public virtual Tcu Tcu { get; set; } = null!;
}
