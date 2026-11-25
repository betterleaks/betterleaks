package gogit

import (
	"slices"
	"time"
)

// editSearch reproduces diffmatchpatch's DiffMainRunes edit script, including
// its half-match split, bisection, and merge cleanup, so that line tokens map
// to the same added lines. It reports run lengths instead of encoding every
// chunk as a string, and reuses the bisection's diagonal arrays.
type editSearch struct {
	deadline time.Time
	v        []int32
}

type editOp int8

const (
	editDelete editOp = -1
	editEqual  editOp = 0
	editInsert editOp = 1
)

// edit is one run of an edit script. Equalities and deletions consume text1,
// equalities and insertions text2, so a run's contents follow from its place
// in the script.
type edit struct {
	op editOp
	n  int
}

// diff compares two token sequences. A search that reaches the deadline falls
// back to replacing its remaining tokens, as DiffMainRunes does.
func (s *editSearch) diff(text1, text2 []rune, timeout time.Duration) []edit {
	s.deadline = time.Now().Add(timeout)
	return s.main(text1, text2)
}

func (s *editSearch) main(text1, text2 []rune) []edit {
	if slices.Equal(text1, text2) {
		if len(text1) > 0 {
			return []edit{{editEqual, len(text1)}}
		}
		return nil
	}
	prefix := commonRunePrefix(text1, text2)
	a, b := text1[prefix:], text2[prefix:]
	suffix := commonRuneSuffix(a, b)
	middle := s.compute(a[:len(a)-suffix], b[:len(b)-suffix])
	diffs := make([]edit, 0, len(middle)+3)
	if prefix != 0 {
		diffs = append(diffs, edit{editEqual, prefix})
	}
	diffs = append(diffs, middle...)
	if suffix != 0 {
		diffs = append(diffs, edit{editEqual, suffix})
	}
	return cleanupMerge(diffs, text1, text2)
}

// compute diffs texts that share neither a prefix nor a suffix.
func (s *editSearch) compute(text1, text2 []rune) []edit {
	if len(text1) == 0 {
		return []edit{{editInsert, len(text2)}}
	}
	if len(text2) == 0 {
		return []edit{{editDelete, len(text1)}}
	}
	long, short, op := text2, text1, editInsert
	if len(text1) > len(text2) {
		long, short, op = text1, text2, editDelete
	}
	if i := indexRunes(long, short, 0); i != -1 {
		return []edit{{op, i}, {editEqual, len(short)}, {op, len(long) - i - len(short)}}
	}
	if len(short) == 1 {
		return []edit{{editDelete, len(text1)}, {editInsert, len(text2)}}
	}
	if hm, ok := halfMatch(text1, text2); ok {
		diffs := s.main(text1[:hm.end1], text2[:hm.end2])
		diffs = append(diffs, edit{editEqual, hm.start1 - hm.end1})
		return append(diffs, s.main(text1[hm.start1:], text2[hm.start2:])...)
	}
	return s.bisect(text1, text2)
}

// halfSplit is a common run that both texts share, at text1[end1:start1] and
// text2[end2:start2].
type halfSplit struct{ end1, start1, end2, start2 int }

var noSplit halfSplit

// halfMatch looks for a common run at least half as long as the longer text.
func halfMatch(text1, text2 []rune) (halfSplit, bool) {
	long, short := text2, text1
	if len(text1) > len(text2) {
		long, short = text1, text2
	}
	if len(long) < 4 || len(short)*2 < len(long) {
		return noSplit, false
	}
	// Seed from the second quarter, then from the third; keep the longer.
	hm1, ok1 := halfMatchAt(long, short, (len(long)+3)/4)
	hm2, ok2 := halfMatchAt(long, short, (len(long)+1)/2)
	var hm halfSplit
	switch {
	case !ok1 && !ok2:
		return noSplit, false
	case !ok2:
		hm = hm1
	case !ok1:
		hm = hm2
	case hm1.start1-hm1.end1 > hm2.start1-hm2.end1:
		hm = hm1
	default:
		hm = hm2
	}
	if len(text1) > len(text2) {
		return hm, true
	}
	return halfSplit{hm.end2, hm.start2, hm.end1, hm.start1}, true
}

// halfMatchAt extends every occurrence in short of the quarter-length seed at
// long[i:], reporting positions in long first.
func halfMatchAt(long, short []rune, i int) (halfSplit, bool) {
	seed := long[i : i+len(long)/4]
	var best halfSplit
	bestLen := 0
	for j := indexRunes(short, seed, 0); j != -1; j = indexRunes(short, seed, j+1) {
		prefix := commonRunePrefix(long[i:], short[j:])
		suffix := commonRuneSuffix(long[:i], short[:j])
		if bestLen < suffix+prefix {
			bestLen = suffix + prefix
			best = halfSplit{i - suffix, i + prefix, j - suffix, j + prefix}
		}
	}
	if bestLen*2 < len(long) {
		return noSplit, false
	}
	return best, true
}

// bisect finds the middle snake of Myers's O(ND) search and diffs each side.
func (s *editSearch) bisect(text1, text2 []rune) []edit {
	n1, n2 := len(text1), len(text2)
	maxD := (n1 + n2 + 1) / 2
	vOffset, vLength := maxD, 2*maxD
	if cap(s.v) < 2*vLength {
		s.v = make([]int32, 2*vLength)
	}
	v1, v2 := s.v[:vLength], s.v[vLength:2*vLength]
	for i := range v1 {
		v1[i] = -1
		v2[i] = -1
	}
	v1[vOffset+1], v2[vOffset+1] = 0, 0
	delta := n1 - n2
	// With an odd total, the forward path collides with the reverse path.
	front := delta%2 != 0
	// Bounds on k that keep paths inside the edit graph.
	k1start, k1end, k2start, k2end := 0, 0, 0, 0
	for d := range maxD {
		if d%16 == 0 && time.Now().After(s.deadline) {
			break
		}
		for k1 := -d + k1start; k1 <= d-k1end; k1 += 2 {
			k1Offset := vOffset + k1
			var x1 int
			if k1 == -d || (k1 != d && v1[k1Offset-1] < v1[k1Offset+1]) {
				x1 = int(v1[k1Offset+1])
			} else {
				x1 = int(v1[k1Offset-1]) + 1
			}
			y1 := x1 - k1
			for x1 < n1 && y1 < n2 && text1[x1] == text2[y1] {
				x1++
				y1++
			}
			v1[k1Offset] = int32(x1)
			switch {
			case x1 > n1:
				k1end += 2
			case y1 > n2:
				k1start += 2
			case front:
				k2Offset := vOffset + delta - k1
				if k2Offset >= 0 && k2Offset < vLength && v2[k2Offset] != -1 {
					if x1 >= n1-int(v2[k2Offset]) {
						return s.split(text1, text2, x1, y1)
					}
				}
			}
		}
		for k2 := -d + k2start; k2 <= d-k2end; k2 += 2 {
			k2Offset := vOffset + k2
			var x2 int
			if k2 == -d || (k2 != d && v2[k2Offset-1] < v2[k2Offset+1]) {
				x2 = int(v2[k2Offset+1])
			} else {
				x2 = int(v2[k2Offset-1]) + 1
			}
			y2 := x2 - k2
			for x2 < n1 && y2 < n2 && text1[n1-x2-1] == text2[n2-y2-1] {
				x2++
				y2++
			}
			v2[k2Offset] = int32(x2)
			switch {
			case x2 > n1:
				k2end += 2
			case y2 > n2:
				k2start += 2
			case !front:
				k1Offset := vOffset + delta - k2
				if k1Offset >= 0 && k1Offset < vLength && v1[k1Offset] != -1 {
					x1 := int(v1[k1Offset])
					// diffmatchpatch derives y from the offset, as here.
					y1 := vOffset + x1 - k1Offset
					if x1 >= n1-x2 {
						return s.split(text1, text2, x1, y1)
					}
				}
			}
		}
	}
	// The deadline passed, or the texts have nothing in common.
	return []edit{{editDelete, n1}, {editInsert, n2}}
}

func (s *editSearch) split(text1, text2 []rune, x, y int) []edit {
	diffs := s.main(text1[:x], text2[:y])
	return append(diffs, s.main(text1[x:], text2[y:])...)
}

// cleanupMerge ports DiffCleanupMerge: it merges adjacent runs, factors
// common affixes out of replacements, and shifts single edits sideways to
// eliminate equalities. It compares run contents in place.
func cleanupMerge(diffs []edit, text1, text2 []rune) []edit {
	diffs = append(diffs, edit{editEqual, 0})
	pointer := 0
	countDelete, countInsert := 0, 0
	lenDelete, lenInsert := 0, 0
	at1, at2 := 0, 0 // where diffs[pointer] begins
	for pointer < len(diffs) {
		switch n := diffs[pointer].n; diffs[pointer].op {
		case editInsert:
			countInsert++
			lenInsert += n
			at2 += n
			pointer++
		case editDelete:
			countDelete++
			lenDelete += n
			at1 += n
			pointer++
		case editEqual:
			if countDelete+countInsert > 1 {
				del, ins := at1-lenDelete, at2-lenInsert
				if countDelete != 0 && countInsert != 0 {
					if c := commonRunePrefix(text2[ins:ins+lenInsert], text1[del:del+lenDelete]); c != 0 {
						if x := pointer - countDelete - countInsert; x > 0 && diffs[x-1].op == editEqual {
							diffs[x-1].n += c
						} else {
							diffs = slices.Insert(diffs, 0, edit{editEqual, c})
							pointer++
						}
						del, ins = del+c, ins+c
						lenDelete, lenInsert = lenDelete-c, lenInsert-c
					}
					if c := commonRuneSuffix(text2[ins:ins+lenInsert], text1[del:del+lenDelete]); c != 0 {
						diffs[pointer].n += c
						lenDelete, lenInsert = lenDelete-c, lenInsert-c
					}
				}
				start := pointer - countDelete - countInsert
				switch {
				case countDelete == 0:
					diffs = slices.Replace(diffs, start, pointer, edit{editInsert, lenInsert})
				case countInsert == 0:
					diffs = slices.Replace(diffs, start, pointer, edit{editDelete, lenDelete})
				default:
					diffs = slices.Replace(diffs, start, pointer, edit{editDelete, lenDelete}, edit{editInsert, lenInsert})
				}
				pointer = start + 1
				if countDelete != 0 {
					pointer++
				}
				if countInsert != 0 {
					pointer++
				}
			} else if pointer != 0 && diffs[pointer-1].op == editEqual {
				diffs[pointer-1].n += n
				diffs = slices.Delete(diffs, pointer, pointer+1)
			} else {
				pointer++
			}
			at1, at2 = at1+n, at2+n
			countDelete, countInsert = 0, 0
			lenDelete, lenInsert = 0, 0
		}
	}
	if diffs[len(diffs)-1].n == 0 {
		diffs = diffs[:len(diffs)-1]
	}
	// Shift single edits surrounded by equalities over one of them, e.g.
	// A<ins>BA</ins>C becomes <ins>AB</ins>AC.
	changes := false
	at1, at2 = 0, 0 // where diffs[pointer-1] begins
	for pointer = 1; pointer < len(diffs)-1; pointer++ {
		prev, cur, next := diffs[pointer-1], diffs[pointer], diffs[pointer+1]
		if prev.op == editEqual && next.op == editEqual {
			// Equalities read from text1; an insertion's text is in text2.
			from, at := text1, at1+prev.n
			if cur.op == editInsert {
				from, at = text2, at2+prev.n
			}
			text := from[at : at+cur.n]
			before := text1[at1 : at1+prev.n]
			after1 := at1 + prev.n
			if cur.op != editInsert {
				after1 += cur.n
			}
			after := text1[after1 : after1+next.n]
			switch {
			case hasRuneSuffix(text, before):
				diffs[pointer+1].n += prev.n
				diffs = slices.Delete(diffs, pointer-1, pointer)
				changes = true
			case hasRunePrefix(text, after):
				diffs[pointer-1].n += next.n
				diffs = slices.Delete(diffs, pointer+1, pointer+2)
				changes = true
			}
		}
		// diffs[pointer] begins where the (possibly shifted) diffs[pointer-1] ends.
		switch d := diffs[pointer-1]; d.op {
		case editEqual:
			at1, at2 = at1+d.n, at2+d.n
		case editDelete:
			at1 += d.n
		case editInsert:
			at2 += d.n
		}
	}
	if changes {
		return cleanupMerge(diffs, text1, text2)
	}
	return diffs
}

func commonRunePrefix(a, b []rune) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

func commonRuneSuffix(a, b []rune) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}

func hasRunePrefix(s, prefix []rune) bool {
	return len(s) >= len(prefix) && slices.Equal(s[:len(prefix)], prefix)
}

func hasRuneSuffix(s, suffix []rune) bool {
	return len(s) >= len(suffix) && slices.Equal(s[len(s)-len(suffix):], suffix)
}

// indexRunes returns the first index of pattern in target at or after from, or
// -1, matching diffmatchpatch's runesIndexOf.
func indexRunes(target, pattern []rune, from int) int {
	if from > len(target)-1 {
		return -1
	}
	from = max(from, 0)
	if len(pattern) == 0 {
		return from
	}
	first := pattern[0]
	for i := from; i <= len(target)-len(pattern); i++ {
		if target[i] == first && slices.Equal(target[i+1:i+len(pattern)], pattern[1:]) {
			return i
		}
	}
	return -1
}
