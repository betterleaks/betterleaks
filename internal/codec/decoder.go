package codec

import (
	"strings"
)

// Decode replaces encoded text and returns segment mappings. Pass the previous
// call's segments as predecessors to preserve original offsets across passes.
func Decode(data string, predecessors []*EncodedSegment) (string, []*EncodedSegment) {
	segments := findEncodedSegments(data, predecessors)

	if len(segments) > 0 {
		var result strings.Builder
		result.Grow(len(data))
		encodedStart := 0
		for _, segment := range segments {
			result.WriteString(data[encodedStart:segment.encoded.start])
			result.WriteString(segment.decodedValue)
			encodedStart = segment.encoded.end
		}

		result.WriteString(data[encodedStart:])
		return result.String(), segments
	}

	return data, segments
}

// findEncodedSegments finds the encoded segments in the data
func findEncodedSegments(data string, predecessors []*EncodedSegment) []*EncodedSegment {
	if len(data) == 0 {
		return []*EncodedSegment{}
	}

	decodedShift := 0
	encodingMatches := findEncodingMatches(data)
	segments := make([]*EncodedSegment, 0, len(encodingMatches))
	for _, m := range encodingMatches {
		encodedValue := data[m.start:m.end]
		decodedValue := m.encoding.decode(encodedValue)

		if len(decodedValue) == 0 {
			continue
		}

		segment := &EncodedSegment{
			predecessors: predecessors,
			original:     toOriginal(predecessors, m.startEnd),
			encoded:      m.startEnd,
			decoded: startEnd{
				m.start + decodedShift,
				m.start + decodedShift + len(decodedValue),
			},
			decodedValue: decodedValue,
			encodings:    m.encoding.kind,
			depth:        1,
		}

		// Shift decoded start and ends based on size changes
		decodedShift += len(decodedValue) - len(encodedValue)

		// Adjust depth and encoding if applicable
		if len(segment.predecessors) != 0 {
			// Set the depth based on the predecessors' depth in the previous pass
			segment.depth = 1 + segment.predecessors[0].depth
			// Adjust encodings
			for _, p := range segment.predecessors {
				if segment.encoded.overlaps(p.decoded) {
					segment.encodings |= p.encodings
				}
			}
		}

		segments = append(segments, segment)
	}

	return segments
}
