using System;
using System.Collections.Generic;

namespace AuthenticationServer.Models;

public partial class SoftwareVersion
{
    public long VersionId { get; set; }

    public string Rxwin { get; set; } = null!;

    public DateTime CreationTimeStamp { get; set; }

    public long? PreviousVersion { get; set; }

    public virtual ICollection<SoftwareVersion> InversePreviousVersionNavigation { get; set; } = new List<SoftwareVersion>();

    public virtual SoftwareVersion? PreviousVersionNavigation { get; set; }

    public virtual ICollection<Tcu> Tcus { get; set; } = new List<Tcu>();
}
