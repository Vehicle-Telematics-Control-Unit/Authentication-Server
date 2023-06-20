namespace AuthenticationServer.Models;

public partial class RequestStatus
{
    public long StatusId { get; set; }

    public string Description { get; set; } = null!;

    public virtual ICollection<ConnectionRequest> ConnectionRequests { get; set; } = new List<ConnectionRequest>();

    public virtual ICollection<LockRequest> LockRequests { get; set; } = new List<LockRequest>();
}
