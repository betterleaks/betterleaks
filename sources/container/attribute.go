package container

// Container provenance is carried through the standard finding attributes.
const (
	AttrImage             = "container.image"
	AttrDigest            = "container.digest"
	AttrIndexDigest       = "container.index_digest"
	AttrConfigDigest      = "container.config_digest"
	AttrPlatform          = "container.platform"
	AttrLayerDigest       = "container.layer_digest"
	AttrDiffID            = "container.diff_id"
	AttrLayerIndex        = "container.layer_index"
	AttrHistoryIndex      = "container.history_index"
	AttrPathState         = "container.path_state"
	AttrHiddenByLayer     = "container.hidden_by_layer"
	AttrMediaType         = "container.media_type"
	AttrRepresentation    = "container.representation"
	ResourceFile          = "container.file"
	ResourceConfig        = "container.config"
	ResourceHistory       = "container.history"
	ResourceManifest      = "container.manifest"
	ResourceIndex         = "container.index"
	ResourceLayerMetadata = "container.layer_metadata"
	ResourceArtifact      = "container.artifact"
)
