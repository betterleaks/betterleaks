package gogit

import (
	"math/bits"
	"slices"
)

// Myers visits about depth² diagonals. The bit-string calculation visits
// len(a)*ceil(len(b)/64) words per pass. Keep small edits on the scalar path.
func wideFrontier(depth, n1, n2 int) bool {
	return depth >= 128 && int64(depth)*int64(depth) >= int64(n1)*int64(n2)/48
}

// wideSplit finds the same middle snake as bisect when the Myers frontier
// grows wide. LCS lengths give prefix edit distances: x+y-2*LCS(a[:x],b[:y]).
// At the middle edit depth we need only the furthest x on each diagonal.
func (s *editSearch) wideSplit(a, b []rune, distance int) []edit {
	// Only destination tokens need masks. ID zero never matches, including
	// when a large deletion contains many distinct parent-only lines.
	ids := make(map[rune]rune)
	current := make([]rune, len(b))
	for i, t := range b {
		if i%16384 == 0 && s.expired() {
			return nil
		}
		id := ids[t]
		if id == 0 {
			id = rune(len(ids) + 1)
			ids[t] = id
		}
		current[i] = id
	}
	old := make([]rune, len(a))
	for i, t := range a {
		if i%16384 == 0 && s.expired() {
			return nil
		}
		old[i] = ids[t]
	}
	masks := make([]uint64, len(ids)+1)
	if distance < 0 {
		lcs := s.lcsFrontier(old, current, masks, nil)
		if s.stopped {
			return nil
		}
		distance = len(a) + len(b) - 2*lcs
	}
	if distance == len(a)+len(b) {
		return []edit{{editDelete, len(a)}, {editInsert, len(b)}}
	}
	forwardDepth, reverseDepth := (distance+1)/2, distance/2
	s.v = resize(s.v, 2*distance+2)
	forward, reverse := s.v[:2*forwardDepth+1], s.v[2*forwardDepth+1:]
	s.lcsFrontier(old, current, masks, forward)
	if s.stopped {
		return nil
	}
	slices.Reverse(old)
	slices.Reverse(current)
	s.lcsFrontier(old, current, masks, reverse)
	if s.stopped {
		return nil
	}

	// For odd distances Myers detects the first forward collision in
	// ascending k. For even distances it checks reverse k in ascending
	// order, hence forward k in descending order.
	start, step := -forwardDepth, 2
	if distance%2 == 0 {
		start, step = forwardDepth, -2
	}
	for k := start; k >= -forwardDepth && k <= forwardDepth; k += step {
		back := len(a) - len(b) - k + reverseDepth
		x := int(forward[k+forwardDepth])
		if uint(back) < uint(len(reverse)) && x >= 0 && int(reverse[back]) >= len(a)-x {
			return s.split(a, b, x, x-k, distance)
		}
	}
	// A replacement also preserves every destination line if the frontiers
	// fail to meet. Never drop a change on the strength of a partial script.
	return []edit{{editDelete, len(a)}, {editInsert, len(b)}}
}

// lcsFrontier uses the Allison-Dix bit-string LCS recurrence (1986,
// doi:10.1016/0020-0190(86)90091-8). Each bit records a column where the
// prefix LCS increases by one. Process 64 columns at a time, so even a
// file with a unique token on every line needs only linear scratch space.
func (s *editSearch) lcsFrontier(a, b []rune, masks []uint64, frontier []int32) int {
	carry := make([]byte, len(a))
	for i := range carry {
		carry[i] = 1 // Low bit of the shifted first word.
	}
	var ranks []int
	depth := len(frontier) / 2
	if frontier != nil {
		ranks = make([]int, len(a))
		for i := range frontier {
			frontier[i] = -1
		}
		if depth <= len(a) {
			frontier[2*depth] = int32(depth)
		}
		if depth <= len(b) {
			frontier[0] = 0
		}
	}
	lcs := 0
	for col := 0; col < len(b); col += 64 {
		block := b[col:min(col+64, len(b))]
		for j, id := range block {
			masks[id] |= uint64(1) << j
		}
		var row uint64
		for i, id := range a {
			if i%16384 == 0 && s.expired() {
				return 0
			}
			above := row
			x := above | masks[id]
			c := uint64(carry[i])
			diff, borrow := bits.Sub64(x, above<<1|c, 0)
			row = x &^ diff
			// A shift out of the high bit and a subtraction borrow cannot
			// both occur: when the high bit is set, (above<<1)|c <= above.
			carry[i] = byte(above>>63 | borrow)
			if frontier != nil {
				ones := bits.OnesCount64(row)
				xpos := i + 1
				dist := xpos + col - 2*ranks[i]
				ranks[i] += ones
				// Bits set in this word lower edit distance; other
				// columns raise it. Most words cannot reach depth.
				if dist-ones <= depth && dist+len(block)-ones >= depth {
					recordFrontier(frontier, depth, xpos, col, len(block), dist, row)
				}
			}
		}
		lcs += bits.OnesCount64(row)
		for _, id := range block {
			masks[id] = 0
		}
	}
	return lcs
}

func recordFrontier(v []int32, depth, x, col, width, dist int, word uint64) {
	for j := 1; j <= width; j++ {
		dist += 1 - 2*int(word&1)
		word >>= 1
		if dist == depth {
			k := x - (col + j)
			v[depth+k] = max(v[depth+k], int32(x))
		}
	}
}
