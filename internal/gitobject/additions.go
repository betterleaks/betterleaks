package gitobject

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// WalkAdditions visits added text hunks from every reachable non-merge commit.
func WalkAdditions(ctx context.Context, repoPath string, yield func(Blob) error) error {
	s, err := openStore(repoPath)
	if err != nil {
		return err
	}
	defer s.close()
	return s.walkAdditions(ctx, yield)
}

func (s *store) walkAdditions(ctx context.Context, yield func(Blob) error) error {
	tips, err := s.references()
	if err != nil {
		return err
	}
	commits, err := s.reachableCommits(ctx, tips)
	if err != nil {
		return err
	}
	sort.Slice(commits, func(i, j int) bool {
		a, aok := s.find(commits[i])
		b, bok := s.find(commits[j])
		if aok && bok {
			return a.offset < b.offset
		}
		return aok
	})
	jobs := make(chan hash, len(commits))
	for _, id := range commits {
		jobs <- id
	}
	close(jobs)
	var workers sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for range max(runtime.GOMAXPROCS(0), 16) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range jobs {
				if err := ctx.Err(); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
				if _, err := s.diffCommit(ctx, id, yield); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
			}
		}()
	}
	workers.Wait()
	if firstErr != nil {
		return fmt.Errorf("walk additions: %w", firstErr)
	}
	return nil
}

func (s *store) reachableCommits(ctx context.Context, tips []hash) ([]hash, error) {
	seen := make(map[hash]bool)
	queue := append([]hash(nil), tips...)
	var commits []hash
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		obj, err := s.load(id)
		if err != nil {
			return nil, err
		}
		if obj.typ == 4 {
			target, err := tagTarget(obj.data)
			if err != nil {
				return nil, err
			}
			queue = append(queue, target)
			continue
		}
		if obj.typ != 1 {
			continue
		}
		commit, err := parseCommit(id, obj.data)
		if err != nil {
			return nil, err
		}
		commits = append(commits, id)
		queue = append(queue, commit.parents...)
	}
	return commits, nil
}

func (s *store) diffCommit(ctx context.Context, id hash, yield func(Blob) error) ([]hash, error) {
	obj, err := s.load(id)
	if err != nil {
		return nil, err
	}
	if obj.typ == 4 {
		target, err := tagTarget(obj.data)
		if err != nil {
			return nil, err
		}
		return []hash{target}, nil
	}
	if obj.typ != 1 {
		return nil, nil
	}
	commit, err := parseCommit(id, obj.data)
	if err != nil {
		return nil, err
	}
	if len(commit.parents) > 1 {
		return commit.parents, nil
	}
	var oldTree hash
	if len(commit.parents) == 1 {
		parentObj, err := s.load(commit.parents[0])
		if err != nil {
			return nil, err
		}
		parent, err := parseCommit(commit.parents[0], parentObj.data)
		if err != nil {
			return nil, err
		}
		oldTree = parent.tree
	}
	var changes []treeChange
	err = s.diffTrees(ctx, oldTree, commit.tree, "", func(path string, oldID, newID hash, mode string) error {
		changes = append(changes, treeChange{path: path, oldID: oldID, newID: newID, mode: mode})
		return nil
	})
	if err != nil {
		return commit.parents, err
	}
	s.pairRenames(changes)
	for _, change := range changes {
		if change.newID == (hash{}) || isTreeMode(change.mode) || (!strings.HasPrefix(change.mode, "100") && change.mode != "120000") {
			continue
		}
		if err := s.emitAdditions(change.path, change.oldID, change.newID, commit.appearance, yield); err != nil {
			return commit.parents, err
		}
	}
	return commit.parents, err
}

type treeEntry struct {
	mode string
	name string
	id   hash
}

type treeChange struct {
	path  string
	oldID hash
	newID hash
	mode  string
}

func isTreeMode(mode string) bool { return mode == "40000" || mode == "040000" }

func (s *store) treeEntries(id hash) ([]treeEntry, error) {
	if id == (hash{}) {
		return nil, nil
	}
	obj, err := s.load(id)
	if err != nil {
		return nil, err
	}
	if obj.typ != 2 {
		return nil, errors.New("tree id is not a tree")
	}
	entries := make([]treeEntry, 0, bytes.Count(obj.data, []byte{0}))
	for data := obj.data; len(data) > 0; {
		space, nul := bytes.IndexByte(data, ' '), bytes.IndexByte(data, 0)
		if space < 1 || nul < space || nul+21 > len(data) {
			return nil, errors.New("invalid tree object")
		}
		var id hash
		copy(id[:], data[nul+1:nul+21])
		entries = append(entries, treeEntry{mode: string(data[:space]), name: string(data[space+1 : nul]), id: id})
		data = data[nul+21:]
	}
	return entries, nil
}

func treeSortName(e treeEntry) string {
	if isTreeMode(e.mode) {
		return e.name + "/"
	}
	return e.name
}

func (s *store) diffTrees(ctx context.Context, oldID, newID hash, prefix string, yield func(string, hash, hash, string) error) error {
	if oldID == newID {
		return nil
	}
	oldEntries, err := s.treeEntries(oldID)
	if err != nil {
		return err
	}
	newEntries, err := s.treeEntries(newID)
	if err != nil {
		return err
	}
	for i, j := 0, 0; i < len(oldEntries) || j < len(newEntries); {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i == len(oldEntries) {
			if err := s.addTreeEntry(ctx, newEntries[j], prefix, yield); err != nil {
				return err
			}
			j++
			continue
		}
		if j == len(newEntries) {
			if err := s.deleteTreeEntry(ctx, oldEntries[i], prefix, yield); err != nil {
				return err
			}
			i++
			continue
		}
		oldEntry, newEntry := oldEntries[i], newEntries[j]
		switch strings.Compare(treeSortName(oldEntry), treeSortName(newEntry)) {
		case -1:
			if err := s.deleteTreeEntry(ctx, oldEntry, prefix, yield); err != nil {
				return err
			}
			i++
		case 1:
			if err := s.addTreeEntry(ctx, newEntry, prefix, yield); err != nil {
				return err
			}
			j++
		default:
			path := joinPath(prefix, newEntry.name)
			if isTreeMode(oldEntry.mode) && isTreeMode(newEntry.mode) {
				err = s.diffTrees(ctx, oldEntry.id, newEntry.id, path, yield)
			} else if isTreeMode(newEntry.mode) {
				err = s.addTreeEntry(ctx, newEntry, prefix, yield)
			} else if oldEntry.id != newEntry.id || oldEntry.mode != newEntry.mode {
				err = yield(path, oldEntry.id, newEntry.id, newEntry.mode)
			}
			if err != nil {
				return err
			}
			i++
			j++
		}
	}
	return nil
}

func (s *store) deleteTreeEntry(ctx context.Context, entry treeEntry, prefix string, yield func(string, hash, hash, string) error) error {
	path := joinPath(prefix, entry.name)
	if isTreeMode(entry.mode) {
		return s.diffTrees(ctx, entry.id, hash{}, path, yield)
	}
	return yield(path, entry.id, hash{}, entry.mode)
}

func (s *store) addTreeEntry(ctx context.Context, entry treeEntry, prefix string, yield func(string, hash, hash, string) error) error {
	path := joinPath(prefix, entry.name)
	if isTreeMode(entry.mode) {
		return s.diffTrees(ctx, hash{}, entry.id, path, yield)
	}
	return yield(path, hash{}, entry.id, entry.mode)
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func (s *store) pairRenames(changes []treeChange) {
	// ponytail: Similarity checks same basenames only; broaden it if renamed
	// files with changed names create a measurable parity gap.
	deleted := make(map[hash][]int)
	for i, change := range changes {
		if change.oldID != (hash{}) && change.newID == (hash{}) && !isTreeMode(change.mode) {
			deleted[change.oldID] = append(deleted[change.oldID], i)
		}
	}
	used := make(map[int]bool)
	for i := range changes {
		change := &changes[i]
		if change.oldID != (hash{}) || change.newID == (hash{}) || isTreeMode(change.mode) {
			continue
		}
		if candidates := deleted[change.newID]; len(candidates) > 0 {
			for _, candidate := range candidates {
				if !used[candidate] {
					change.oldID = changes[candidate].oldID
					used[candidate] = true
					break
				}
			}
			if change.oldID != (hash{}) {
				continue
			}
		}

		best, bestScore := -1, 0.0
		for candidate := range changes {
			old := changes[candidate]
			if used[candidate] || old.oldID == (hash{}) || old.newID != (hash{}) || path.Base(old.path) != path.Base(change.path) {
				continue
			}
			score := s.lineSimilarity(old.oldID, change.newID)
			if score > bestScore {
				best, bestScore = candidate, score
			}
		}
		if bestScore >= 0.5 {
			change.oldID = changes[best].oldID
			used[best] = true
		}
	}
}

func (s *store) lineSimilarity(a, b hash) float64 {
	old, err := s.load(a)
	if err != nil || old.typ != 3 {
		return 0
	}
	new, err := s.load(b)
	if err != nil || new.typ != 3 {
		return 0
	}
	oldLines, newLines := lines(old.data), lines(new.data)
	if len(oldLines) == 0 || len(newLines) == 0 {
		return 0
	}
	counts := make(map[string]int, len(oldLines))
	for _, line := range oldLines {
		counts[line]++
	}
	common := 0
	for _, line := range newLines {
		if counts[line] > 0 {
			common++
			counts[line]--
		}
	}
	return float64(common) / float64(max(len(oldLines), len(newLines)))
}

func (s *store) emitAdditions(path string, oldID, newID hash, appearance Appearance, yield func(Blob) error) error {
	newObj, err := s.load(newID)
	if err != nil {
		return err
	}
	if newObj.typ != 3 {
		return nil
	}
	var old []byte
	if oldID != (hash{}) {
		oldObj, err := s.load(oldID)
		if err != nil {
			return err
		}
		if oldObj.typ == 3 {
			old = oldObj.data
		}
	}
	appearance.Path = path
	if isBinary(newObj.data) || isBinary(old) {
		if bytes.Equal(old, newObj.data) {
			return nil
		}
		return yield(Blob{Hash: newID.String(), Size: int64(len(newObj.data)), Content: bytes.NewReader(newObj.data), StartLine: 1, Binary: true, Appearance: appearance})
	}
	for _, hunk := range addedHunks(old, newObj.data) {
		raw := strings.Join(hunk.lines, "\n")
		if raw != "" {
			raw += "\n"
		}
		if err := yield(Blob{Hash: newID.String(), Size: int64(len(raw)), Content: strings.NewReader(raw), StartLine: hunk.start, Appearance: appearance}); err != nil {
			return err
		}
	}
	return nil
}

func isBinary(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0
}

type addedHunk struct {
	start int
	lines []string
}

func addedHunks(old, new []byte) []addedHunk {
	if bytes.Equal(old, new) {
		return nil
	}
	oldLines, newLines := lines(old), lines(new)
	matched := patienceMatches(oldLines, newLines)
	var hunks []addedHunk
	for newAt, line := range newLines {
		if matched[newAt] {
			continue
		}
		lineNo := newAt + 1
		if len(hunks) == 0 || hunks[len(hunks)-1].start+len(hunks[len(hunks)-1].lines) != lineNo {
			hunks = append(hunks, addedHunk{start: lineNo})
		}
		hunks[len(hunks)-1].lines = append(hunks[len(hunks)-1].lines, line)
	}
	return hunks
}

// patienceMatches uses unique-line anchors and an increasing subsequence to
// avoid treating reordered source blocks as entirely new content.
func patienceMatches(old, new []string) []bool {
	matched := make([]bool, len(new))
	var visit func(int, int, int, int)
	visit = func(olo, ohi, nlo, nhi int) {
		for olo < ohi && nlo < nhi && old[olo] == new[nlo] {
			matched[nlo] = true
			olo++
			nlo++
		}
		for olo < ohi && nlo < nhi && old[ohi-1] == new[nhi-1] {
			matched[nhi-1] = true
			ohi--
			nhi--
		}
		if olo == ohi || nlo == nhi {
			return
		}
		type occ struct{ n, pos int }
		oc, nc := make(map[string]occ, ohi-olo), make(map[string]occ, nhi-nlo)
		for i := olo; i < ohi; i++ {
			x := oc[old[i]]
			x.n++
			x.pos = i
			oc[old[i]] = x
		}
		for i := nlo; i < nhi; i++ {
			x := nc[new[i]]
			x.n++
			x.pos = i
			nc[new[i]] = x
		}
		type anchor struct{ o, n int }
		c := make([]anchor, 0, min(ohi-olo, nhi-nlo))
		for i := nlo; i < nhi; i++ {
			a, b := oc[new[i]], nc[new[i]]
			if a.n == 1 && b.n == 1 {
				c = append(c, anchor{a.pos, i})
			}
		}
		if len(c) == 0 {
			positions := make(map[string][]int, ohi-olo)
			for i := olo; i < ohi; i++ {
				positions[old[i]] = append(positions[old[i]], i)
			}
			at := olo
			for i := nlo; i < nhi; i++ {
				for _, pos := range positions[new[i]] {
					if pos >= at {
						matched[i] = true
						at = pos + 1
						break
					}
				}
			}
			return
		}
		tails, prev := make([]int, 0, len(c)), make([]int, len(c))
		for i, a := range c {
			j := sort.Search(len(tails), func(j int) bool { return c[tails[j]].o >= a.o })
			prev[i] = -1
			if j > 0 {
				prev[i] = tails[j-1]
			}
			if j == len(tails) {
				tails = append(tails, i)
			} else {
				tails[j] = i
			}
		}
		anchors := make([]anchor, len(tails))
		for i, j := len(anchors)-1, tails[len(tails)-1]; i >= 0; i-- {
			anchors[i] = c[j]
			j = prev[j]
		}
		lo, ln := olo, nlo
		for _, a := range anchors {
			visit(lo, a.o, ln, a.n)
			matched[a.n] = true
			lo, ln = a.o+1, a.n+1
		}
		visit(lo, ohi, ln, nhi)
	}
	visit(0, len(old), 0, len(new))
	return matched
}

func lines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	parts := strings.Split(string(data), "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
