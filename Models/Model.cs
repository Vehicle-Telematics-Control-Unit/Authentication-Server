using System;
using System.Collections.Generic;

namespace AuthenticationServer.Models;

public partial class Model
{
    public long Id { get; set; }

    public string Name { get; set; } = null!;

    public virtual ICollection<ModelsFeature> ModelsFeatures { get; set; } = new List<ModelsFeature>();

    public virtual ICollection<Tcu> Tcus { get; set; } = new List<Tcu>();
}
