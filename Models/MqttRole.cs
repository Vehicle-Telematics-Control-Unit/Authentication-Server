namespace AuthenticationServer.Models;

public partial class MqttRole
{
    public long RoleId { get; set; }

    public string Topic { get; set; } = null!;

    public bool? CanPublish { get; set; }

    public bool? CanSubscribe { get; set; }

    public virtual ICollection<DevicesMqttRole> DevicesMqttRoles { get; set; } = new List<DevicesMqttRole>();

    public virtual ICollection<TcuMqttRole> TcuMqttRoles { get; set; } = new List<TcuMqttRole>();
}
