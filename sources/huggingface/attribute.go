package huggingface

// Attribute keys and resource values retain their serialized provider names.
const (
	ResourceRepo          = "huggingface.repository"
	ResourceDiscussion    = "huggingface.discussion"
	ResourcePR            = "huggingface.pr"
	ResourceComment       = "huggingface.comment"
	ResourceBucket        = "huggingface.bucket"
	AttrOwner             = "huggingface.owner"
	AttrRepo              = "huggingface.repo"
	AttrRepoType          = "huggingface.repo_type"
	AttrRepoURL           = "huggingface.repo_url"
	AttrVisibility        = "huggingface.visibility"
	AttrDiscussionNumber  = "huggingface.discussion.number"
	AttrCommentID         = "huggingface.comment.id"
	AttrAuthor            = "huggingface.author"
	AttrCommunityResource = "huggingface.community.resource"
	AttrBucket            = "huggingface.bucket"
	AttrBucketURL         = "huggingface.bucket_url"
	AttrBucketPath        = "huggingface.bucket.path"
	AttrBucketSize        = "huggingface.bucket.size"
	AttrBucketMTime       = "huggingface.bucket.mtime"
	AttrBucketXetHash     = "huggingface.bucket.xet_hash"
)
