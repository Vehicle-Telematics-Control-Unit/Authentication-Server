using System;
using System.Collections.Generic;

namespace AuthenticationServer.Models;

public partial class Feature
{
    public long FeatureId { get; set; }

    public string FeatureName { get; set; } = null!;

    public DateTime ReleaseDate { get; set; }

    public string Description { get; set; } = null!;

    public long AppId { get; set; }

    public bool IsActive { get; set; }

    public virtual App App { get; set; } = null!;

    public virtual ICollection<App> Apps { get; set; } = new List<App>();

    public virtual ICollection<ModelsFeature> ModelsFeatures { get; set; } = new List<ModelsFeature>();

    public virtual ICollection<Tcufeature> Tcufeatures { get; set; } = new List<Tcufeature>();
}
