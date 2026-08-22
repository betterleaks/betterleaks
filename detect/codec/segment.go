package codec

import (
	"strconv"
)

// EncodedSegment represents a portion of text that is encoded in some way.
type EncodedSegment struct {
	// predecessors are all of the segments from the previous decoding pass
	predecessors []*EncodedSegment

	// original start/end indices before decoding
	original startEnd

	// encoded start/end indices relative to the previous decoding pass.
	// If it's a top level segment, original and encoded will be the
	// same.
	encoded startEnd

	// decoded start/end indices in this pass after decoding
	decoded startEnd

	// decodedValue contains the decoded string for this segment
	decodedValue string

	// encodings is the encodings that make up this segment. encodingKind
	// can be or'd together to hold multiple encodings
	encodings encodingKind

	// depth is how many decoding passes it took to decode this segment
	depth int
}

// Tags returns additional meta data tags related to the types of segments
func Tags(segments []*EncodedSegment) []string {
	return AppendTags(nil, segments)
}

// AppendTags appends decode metadata to dst.
func AppendTags(dst []string, segments []*EncodedSegment) []string {
	if len(segments) == 0 {
		return dst
	}

	// Since decoding is done in passes, the depth of all the segments
	// should be the same
	depth := segments[0].depth

	// Collect the encodings from the segments
	encodings := segments[0].encodings
	for i := 1; i < len(segments); i++ {
		encodings |= segments[i].encodings
	}

	for i, name := range encodingNames {
		if int(encodings)&(1<<i) != 0 {
			dst = append(dst, "decoded:"+name)
		}
	}
	dst = append(dst, "decode-depth:"+strconv.Itoa(depth))
	return dst
}

// CurrentLine returns from the start of the line containing the segments
// to the end of the line where the segment ends.
func CurrentLine(segments []*EncodedSegment, currentRaw string) string {
	// Return the whole thing if no segments are provided
	if len(segments) == 0 {
		return currentRaw
	}

	start := 0
	end := len(currentRaw)

	// Merge the ranges together into a single decoded value
	decoded := segments[0].decoded
	for i := 1; i < len(segments); i++ {
		decoded = decoded.merge(segments[i].decoded)
	}

	// Find the start of the range
	for i := decoded.start; i > -1; i-- {
		c := currentRaw[i]
		if c == '\n' {
			start = i
			break
		}
	}

	// Find the end of the range
	for i := decoded.end; i < end; i++ {
		c := currentRaw[i]
		if c == '\n' {
			end = i
			break
		}
	}

	return currentRaw[start:end]
}

// CurrentLineBytes is the byte-oriented form of CurrentLine.
func CurrentLineBytes(segments []*EncodedSegment, currentRaw []byte) []byte {
	if len(segments) == 0 {
		return currentRaw
	}
	start := 0
	end := len(currentRaw)
	decoded := segments[0].decoded
	for i := 1; i < len(segments); i++ {
		decoded = decoded.merge(segments[i].decoded)
	}
	for i := decoded.start; i > -1; i-- {
		if currentRaw[i] == '\n' {
			start = i
			break
		}
	}
	for i := decoded.end; i < end; i++ {
		if currentRaw[i] == '\n' {
			end = i
			break
		}
	}
	return currentRaw[start:end]
}

// AdjustMatchRange maps a range from the current decode pass back to its
// location in the original text.
func AdjustMatchRange(segments []*EncodedSegment, start, end int) (int, int) {
	if len(segments) == 0 {
		return start, end
	}
	adjusted := toOriginal(segments, startEnd{start, end})
	return adjusted.start, adjusted.end
}

// SegmentsWithDecodedOverlap the segments where the start and end overlap its
// decoded range
func SegmentsWithDecodedOverlap(segments []*EncodedSegment, start, end int) []*EncodedSegment {
	return AppendSegmentsWithDecodedOverlap(nil, segments, start, end)
}

// AppendSegmentsWithDecodedOverlap appends segments whose decoded range
// overlaps start:end to dst.
func AppendSegmentsWithDecodedOverlap(dst, segments []*EncodedSegment, start, end int) []*EncodedSegment {
	se := startEnd{start, end}
	for _, segment := range segments {
		if segment.decoded.overlaps(se) {
			dst = append(dst, segment)
		}
	}
	return dst
}

// toOriginal maps a start/end to its start/end in the original text
// the provided start/end should be relative to the segment's decoded value
func toOriginal(predecessors []*EncodedSegment, decoded startEnd) startEnd {
	if len(predecessors) == 0 {
		return decoded
	}

	// Map the decoded value one level up where it was encoded
	encoded := startEnd{}

	for _, p := range predecessors {
		if !p.decoded.overlaps(decoded) {
			continue // Not in scope
		}

		// If fully contained, return the segments original start/end
		if p.decoded.contains(decoded) {
			return p.original
		}

		// Map the value to be relative to the predecessors's decoded values
		if encoded.end == 0 {
			encoded = p.encoded.add(p.decoded.overflow(decoded))
		} else {
			encoded = encoded.merge(p.encoded.add(p.decoded.overflow(decoded)))
		}
	}

	// Should only get here if the thing passed in wasn't in a decoded
	// value. This shouldn't be the case
	if encoded.end == 0 {
		return decoded
	}

	// Climb up another level
	// (NOTE: each segment references all the predecessors)
	return toOriginal(predecessors[0].predecessors, encoded)
}
