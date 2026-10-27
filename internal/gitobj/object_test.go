package gitobj

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func encoded(t testing.TB, format ObjectFormat, kind ObjectType, raw string) *MemoryObject {
	t.Helper()
	o := NewMemoryObject(FromObjectFormat(format))
	o.SetType(kind)
	w, err := o.Writer()
	require.NoError(t, err)
	_, err = w.Write([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return o
}

func TestCommitDecoder(t *testing.T) {
	for _, f := range []ObjectFormat{SHA1, SHA256} {
		t.Run(string(f), func(t *testing.T) {
			size := FromObjectFormat(f).Size() * 2
			id := strings.Repeat("a", size)
			raw := fmt.Sprintf("tree %s\nparent %s\nauthor A <a@example.test> 1234567890 -0530\ncommitter C <c@example.test> 1234567891 +0330\ngpgsig -----BEGIN\n continuation\nparent invalid-duplicate\nauthor ignored <bad@example.test> 0 +0000\n\nmessage\n\nlast\n", id, id)
			o := encoded(t, f, CommitObject, raw)
			c, err := DecodeCommit(nil, o)
			require.NoError(t, err)
			require.Equal(t, id, c.TreeHash.String())
			require.Equal(t, []Hash{NewHash(id)}, c.ParentHashes)
			require.Equal(t, "A", c.Author.Name)
			require.Equal(t, "C", c.Committer.Name)
			require.Equal(t, "message\n\nlast\n", c.Message)
			if f == SHA1 {
				var want object.Commit
				require.NoError(t, want.Decode(v5Object{o, plumbing.NewHash(o.Hash().String())}))
				require.Equal(t, want.Author, c.Author)
				require.Equal(t, want.Committer, c.Committer)
				require.Equal(t, want.Message, c.Message)
			}
			for _, bad := range []string{"", "author A\ntree " + id, "tree bad\n", "tree " + id + "\nparent bad\n"} {
				_, err := DecodeCommit(nil, encoded(t, f, CommitObject, bad))
				require.Error(t, err)
			}
		})
	}
}

func TestTagDecoder(t *testing.T) {
	for _, f := range []ObjectFormat{SHA1, SHA256} {
		id := strings.Repeat("b", FromObjectFormat(f).Size()*2)
		raw := fmt.Sprintf("object %s\ntype commit\ntag release\ntagger A <a@example.test> 1234567890 +0000\ntag ignored\nobject invalid-duplicate\n\nmessage\n-----BEGIN SSH SIGNATURE-----\nnot message\n", id)
		tag, err := DecodeTag(nil, encoded(t, f, TagObject, raw))
		require.NoError(t, err)
		require.Equal(t, id, tag.Target.String())
		require.Equal(t, "release", tag.Name)
		require.Equal(t, "message\n", tag.Message)
		for _, bad := range []string{"", "type commit\nobject " + id, "object bad\ntype commit\ntag a\n", "object " + id + "\ntag a\n"} {
			_, err := DecodeTag(nil, encoded(t, f, TagObject, bad))
			require.Error(t, err)
		}
	}
}

func TestTagCertificateIsMessage(t *testing.T) {
	for _, f := range []ObjectFormat{SHA1, SHA256} {
		id := strings.Repeat("b", FromObjectFormat(f).Size()*2)
		message := "release notes\n-----BEGIN CERTIFICATE-----\nTOKEN_AFTER_CERTIFICATE\n-----END CERTIFICATE-----\n"
		raw := fmt.Sprintf("object %s\ntype commit\ntag release\n\n%s", id, message)
		tag, err := DecodeTag(nil, encoded(t, f, TagObject, raw))
		require.NoError(t, err)
		require.Equal(t, message, tag.Message)
		// A real signature following a certificate still ends the message.
		tag, err = DecodeTag(nil, encoded(t, f, TagObject, raw+"-----BEGIN SIGNED MESSAGE-----\nsignature\n"))
		require.NoError(t, err)
		require.Equal(t, message, tag.Message)
	}
}

func TestTreeModesAndWidths(t *testing.T) {
	for _, f := range []ObjectFormat{SHA1, SHA256} {
		id := NewHash(strings.Repeat("a", FromObjectFormat(f).Size()*2))
		raw := "100664 regular\x00" + string(id.Bytes()) + "100775 executable\x00" + string(id.Bytes()) + "040775 dir\x00" + string(id.Bytes())
		tree, err := DecodeTree(nil, encoded(t, f, TreeObject, raw))
		require.NoError(t, err)
		require.Len(t, tree.Entries, 3)
		require.Equal(t, filemode.Regular, tree.Entries[0].Mode)
		require.Equal(t, filemode.Executable, tree.Entries[1].Mode)
		require.Equal(t, filemode.Dir, tree.Entries[2].Mode)
		require.Equal(t, id, tree.Entries[2].Hash)
		for _, bad := range []string{"100644 x", "100644 \x00" + string(id.Bytes()), "100644 x\x00" + string(id.Bytes()[:id.Size()-1]), "wrong x\x00" + string(id.Bytes())} {
			_, err := DecodeTree(nil, encoded(t, f, TreeObject, bad))
			require.Error(t, err)
		}
	}
}

func FuzzObjectDecoders(f *testing.F) {
	f.Add("tree "+strings.Repeat("a", 40)+"\n\nmessage\n", false)
	f.Add("100644 x\x00"+strings.Repeat("x", 32), true)
	f.Fuzz(func(t *testing.T, data string, sha256 bool) {
		if len(data) > 65536 {
			t.Skip()
		}
		format := SHA1
		if sha256 {
			format = SHA256
		}
		_, _ = DecodeCommit(nil, encoded(t, format, CommitObject, data))
		_, _ = DecodeTag(nil, encoded(t, format, TagObject, data))
		_, _ = DecodeTree(nil, encoded(t, format, TreeObject, data))
		_ = NewHash(data)
	})
}
