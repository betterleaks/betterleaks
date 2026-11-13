package codec

import (
	"strings"
)

// Decode replaces encoded text and returns segment mappings. Pass the previous
// call's segments as predecessors to preserve original offsets across passes.
func Decode(data string, predecessors []*EncodedSegment) (string, []*EncodedSegment) {
	decoded, segments, _ := DecodeWithBudget(data, predecessors, nil)
	return decoded, segments
}

// DecodeWithBudget reserves allocation work before collecting encoding matches,
// decoding values, or constructing the output. A nil reserve disables accounting.
// Failure returns no partial decoded text or segments.
func DecodeWithBudget(data string, predecessors []*EncodedSegment, reserve func(int64) error) (string, []*EncodedSegment, error) {
	segments, err := findEncodedSegmentsWithBudget(data, predecessors, reserve)
	if err != nil {
		return "", nil, err
	}

	if len(segments) > 0 {
		if reserve != nil {
			if err := reserve(2 * int64(len(data))); err != nil {
				return "", nil, err
			}
		}
		var result strings.Builder
		result.Grow(len(data))
		encodedStart := 0
		for _, segment := range segments {
			result.WriteString(data[encodedStart:segment.encoded.start])
			result.WriteString(segment.decodedValue)
			encodedStart = segment.encoded.end
		}

		result.WriteString(data[encodedStart:])
		return result.String(), segments, nil
	}

	return data, segments, nil
}

func findEncodedSegmentsWithBudget(data string, predecessors []*EncodedSegment, reserve func(int64) error) ([]*EncodedSegment, error) {
	if len(data) == 0 {
		return []*EncodedSegment{}, nil
	}

	decodedShift := 0
	encodingMatches, err := findEncodingMatchesWithBudget(data, reserve)
	if err != nil {
		return nil, err
	}
	segments := make([]*EncodedSegment, 0, len(encodingMatches))
	for _, m := range encodingMatches {
		encodedValue := data[m.start:m.end]
		if reserve != nil {
			if err := reserve(256 + 4*int64(len(encodedValue))); err != nil {
				return nil, err
			}
		}
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

	return segments, nil
}
