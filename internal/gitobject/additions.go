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
	// Discovery and pack reading deliberately use separate pools. Discovery is
	// tree/commit heavy; the second stage sees a bounded global view of blobs and
	// can therefore inflate each pack object once for all of its appearances.
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan hash, len(commits))
	for _, id := range commits {
		jobs <- id
	}
	close(jobs)
	candidates := make(chan blobCandidate, 4096)
	var discover sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	recordErr := func(err error) {
		if err == nil || errors.Is(err, context.Canceled) {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		errMu.Unlock()
	}
	for range max(runtime.GOMAXPROCS(0), 16) {
		discover.Add(1)
		go func() {
			defer discover.Done()
			for id := range jobs {
				if err := workCtx.Err(); err != nil {
					return
				}
				err := s.diffCommit(workCtx, id, func(candidate blobCandidate) error {
					select {
					case candidates <- candidate:
						return nil
					case <-workCtx.Done():
						return workCtx.Err()
					}
				})
				if err != nil {
					recordErr(err)
					return
				}
			}
		}()
	}
	go func() { discover.Wait(); close(candidates) }()

	const candidateWindow = 65536
	window := make([]blobCandidate, 0, candidateWindow)
	for candidate := range candidates {
		window = append(window, candidate)
		if len(window) == candidateWindow {
			if err := s.processCandidateWindow(workCtx, window, yield); err != nil {
				recordErr(err)
			}
			window = window[:0]
		}
	}
	if len(window) > 0 {
		if err := s.processCandidateWindow(workCtx, window, yield); err != nil {
			recordErr(err)
		}
	}
	errMu.Lock()
	err = firstErr
	errMu.Unlock()
	if err != nil {
		return fmt.Errorf("walk additions: %w", err)
	}
	return ctx.Err()
}

type candidateGroup struct {
	id         hash
	loc        location
	packed     bool
	candidates []blobCandidate
}

// processCandidateWindow is the pack-oriented half of the walk. The window is
// bounded, but is global across commit walkers: duplicate blobs collapse into a
// single inflate and groups are submitted in physical pack order.
func (s *store) processCandidateWindow(ctx context.Context, candidates []blobCandidate, yield func(Blob) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	groups := make([]candidateGroup, 0, len(candidates))
	packed := make(map[location]int, len(candidates))
	loose := make(map[hash]int)
	for _, candidate := range candidates {
		change := candidate.change
		if change.newID == (hash{}) || isTreeMode(change.mode) || (!strings.HasPrefix(change.mode, "100") && change.mode != "120000") {
			continue
		}
		if loc, ok := s.find(change.newID); ok {
			if n, exists := packed[loc]; exists {
				groups[n].candidates = append(groups[n].candidates, candidate)
				continue
			}
			packed[loc] = len(groups)
			groups = append(groups, candidateGroup{id: change.newID, loc: loc, packed: true, candidates: []blobCandidate{candidate}})
		} else if n, exists := loose[change.newID]; exists {
			groups[n].candidates = append(groups[n].candidates, candidate)
		} else {
			loose[change.newID] = len(groups)
			groups = append(groups, candidateGroup{id: change.newID, candidates: []blobCandidate{candidate}})
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if a.packed != b.packed {
			return a.packed
		}
		if !a.packed {
			return bytes.Compare(a.id[:], b.id[:]) < 0
		}
		if a.loc.pack.order != b.loc.pack.order {
			return a.loc.pack.order < b.loc.pack.order
		}
		return a.loc.offset < b.loc.offset
	})
	workers := max(runtime.GOMAXPROCS(0), 16)
	jobs := make(chan candidateGroup, workers*2)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for group := range jobs {
				if ctx.Err() != nil {
					return
				}
				obj, err := s.load(group.id)
				if err == nil && obj.typ == 3 {
					for _, candidate := range group.candidates {
						err = s.emitAdditionsObject(candidate.change.path, candidate.change.oldID, group.id, obj, candidate.appearance, yield)
						if err != nil {
							break
						}
					}
				}
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					errMu.Unlock()
					return
				}
			}
		}()
	}
	for _, group := range groups {
		errMu.Lock()
		failed := firstErr != nil
		errMu.Unlock()
		if failed {
			break
		}
		select {
		case jobs <- group:
		case <-ctx.Done():
			break
		}
	}
	close(jobs)
	wg.Wait()
	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	return err
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

func (s *store) diffCommit(ctx context.Context, id hash, yield func(blobCandidate) error) error {
	obj, err := s.load(id)
	if err != nil || obj.typ != 1 {
		return err
	}
	commit, err := parseCommit(id, obj.data)
	if err != nil {
		return err
	}
	if len(commit.parents) > 1 {
		return nil
	}
	var oldTree hash
	if len(commit.parents) == 1 {
		parentObj, err := s.load(commit.parents[0])
		if err != nil {
			return err
		}
		parent, err := parseCommit(commit.parents[0], parentObj.data)
		if err != nil {
			return err
		}
		oldTree = parent.tree
	}
	var changes []treeChange
	err = s.diffTrees(ctx, oldTree, commit.tree, "", func(path string, oldID, newID hash, mode string) error {
		changes = append(changes, treeChange{path: path, oldID: oldID, newID: newID, mode: mode})
		return nil
	})
	if err != nil {
		return err
	}
	s.pairRenames(changes)
	for _, change := range changes {
		if change.newID == (hash{}) || isTreeMode(change.mode) || (!strings.HasPrefix(change.mode, "100") && change.mode != "120000") {
			continue
		}
		if err := yield(blobCandidate{change: change, appearance: commit.appearance}); err != nil {
			return err
		}
	}
	return nil
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

type blobCandidate struct {
	change     treeChange
	appearance Appearance
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
	// The similarity fallback only considers equal basenames. Index them once
	// instead of walking every deletion for every addition; large commits made
	// that quadratic search a material part of the entire scan.
	deletedByBase := make(map[string][]int)
	for i, change := range changes {
		if change.oldID != (hash{}) && change.newID == (hash{}) && !isTreeMode(change.mode) {
			deleted[change.oldID] = append(deleted[change.oldID], i)
			deletedByBase[path.Base(change.path)] = append(deletedByBase[path.Base(change.path)], i)
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
		for _, candidate := range deletedByBase[path.Base(change.path)] {
			old := changes[candidate]
			if used[candidate] {
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
	return s.emitAdditionsObject(path, oldID, newID, newObj, appearance, yield)
}

func (s *store) emitAdditionsObject(path string, oldID, newID hash, newObj object, appearance Appearance, yield func(Blob) error) error {
	if newObj.typ != 3 {
		return nil
	}
	appearance.Path = path
	if isBinary(newObj.data) {
		return yield(Blob{Hash: newID.String(), Size: int64(len(newObj.data)), Content: bytes.NewReader(newObj.data), StartLine: 1, Binary: true, Appearance: appearance})
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
	if isBinary(old) {
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
		if err := yield(Blob{Hash: newID.String(), Size: int64(len(raw)), Text: raw, StartLine: hunk.start, Appearance: appearance}); err != nil {
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
