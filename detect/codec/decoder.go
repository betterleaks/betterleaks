package codec

import (
	"bytes"
	"sync"

	"github.com/betterleaks/betterleaks/logging"
)

// Decoder decodes various types of data in place
type Decoder struct {
	decodedMap    map[string]string
	byteResult    *[]byte
	ownedSegments *[]*EncodedSegment
}

const (
	maxPooledDecodedBytes   = 256 * 1024
	maxPooledDecodedEntries = 256
)

var decodedBytesPool = sync.Pool{
	New: func() any {
		data := []byte(nil)
		return &data
	},
}

var encodedSegmentPool = sync.Pool{
	New: func() any { return new(EncodedSegment) },
}

var encodedSegmentListPool = sync.Pool{
	New: func() any {
		segments := make([]*EncodedSegment, 0, 8)
		return &segments
	},
}

func (d *Decoder) newSegment(segment EncodedSegment) *EncodedSegment {
	value := encodedSegmentPool.Get().(*EncodedSegment)
	*value = segment
	if d.ownedSegments == nil {
		d.ownedSegments = encodedSegmentListPool.Get().(*[]*EncodedSegment)
	}
	*d.ownedSegments = append(*d.ownedSegments, value)
	return value
}

func getDecodedBytes(size int) *[]byte {
	buffer := decodedBytesPool.Get().(*[]byte)
	if cap(*buffer) < size {
		*buffer = make([]byte, 0, size)
	} else {
		*buffer = (*buffer)[:0]
	}
	return buffer
}

func putDecodedBytes(buffer *[]byte) {
	if buffer == nil || cap(*buffer) > maxPooledDecodedBytes {
		return
	}
	*buffer = (*buffer)[:0]
	decodedBytesPool.Put(buffer)
}

// NewDecoder creates a default decoder struct
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode returns the data with the values decoded in place along with the
// encoded segment metadata for the next pass of decoding. Passing no
// predecessors starts a new chain and releases scratch from the prior chain.
func (d *Decoder) Decode(data string, predecessors []*EncodedSegment) (string, []*EncodedSegment) {
	d.beginChain(predecessors)
	segments := d.findEncodedSegments(data, predecessors)

	if len(segments) > 0 {
		result := bytes.NewBuffer(make([]byte, 0, len(data)))
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

// DecodeBytes is the byte-oriented form of Decode. When no encoding succeeds,
// it returns the original borrowed slice without allocating. A decoded result
// is owned by Decoder and remains valid until the next successful DecodeBytes
// call, a new chain is started with no predecessors, or Release is called.
func (d *Decoder) DecodeBytes(data []byte, predecessors []*EncodedSegment) ([]byte, []*EncodedSegment) {
	d.beginChain(predecessors)
	segments := d.findEncodedSegmentsBytes(data, predecessors)
	if len(segments) == 0 {
		return data, segments
	}

	next := getDecodedBytes(len(data))
	result := (*next)[:0]
	encodedStart := 0
	for _, segment := range segments {
		result = append(result, data[encodedStart:segment.encoded.start]...)
		result = append(result, segment.decodedValue...)
		encodedStart = segment.encoded.end
	}
	result = append(result, data[encodedStart:]...)
	*next = result
	putDecodedBytes(d.byteResult)
	d.byteResult = next
	return result, segments
}

func (d *Decoder) beginChain(predecessors []*EncodedSegment) {
	if len(predecessors) != 0 {
		return
	}
	if d.byteResult != nil || d.ownedSegments != nil || len(d.decodedMap) != 0 {
		d.Release()
	}
}

// Release returns decoding scratch space to the shared pools. Any decoded byte
// slice or encoded-segment metadata returned by this Decoder must no longer be
// used afterward.
func (d *Decoder) Release() {
	putDecodedBytes(d.byteResult)
	d.byteResult = nil
	// String-backed decoding caches substring keys. Clear them at the fragment
	// boundary so a reusable worker cannot retain the caller's entire source
	// string through a small encoded token.
	if len(d.decodedMap) > maxPooledDecodedEntries {
		d.decodedMap = nil
	} else {
		clear(d.decodedMap)
	}
	if d.ownedSegments != nil {
		for _, segment := range *d.ownedSegments {
			*segment = EncodedSegment{}
			encodedSegmentPool.Put(segment)
		}
		*d.ownedSegments = (*d.ownedSegments)[:0]
		encodedSegmentListPool.Put(d.ownedSegments)
		d.ownedSegments = nil
	}
}

// findEncodedSegments finds the encoded segments in the data
func (d *Decoder) findEncodedSegments(data string, predecessors []*EncodedSegment) []*EncodedSegment {
	if len(data) == 0 {
		return []*EncodedSegment{}
	}

	start := 0
	if d.ownedSegments != nil {
		start = len(*d.ownedSegments)
	}
	collector := decodedSegmentCollector{
		decoder:      d,
		data:         data,
		predecessors: predecessors,
	}
	visitEncodingMatches(data, &collector)
	if d.ownedSegments == nil {
		return nil
	}
	return (*d.ownedSegments)[start:]
}

func (d *Decoder) findEncodedSegmentsBytes(data []byte, predecessors []*EncodedSegment) []*EncodedSegment {
	if len(data) == 0 {
		return []*EncodedSegment{}
	}

	start := 0
	if d.ownedSegments != nil {
		start = len(*d.ownedSegments)
	}
	collector := decodedBytesSegmentCollector{
		decoder:      d,
		data:         data,
		predecessors: predecessors,
	}
	visitEncodingMatches(data, &collector)
	if d.ownedSegments == nil {
		return nil
	}
	return (*d.ownedSegments)[start:]
}

type decodedSegmentCollector struct {
	decoder      *Decoder
	data         string
	predecessors []*EncodedSegment
	decodedShift int
}

func (c *decodedSegmentCollector) add(m encodingMatch) {
	encodedValue := c.data[m.start:m.end]
	decodedValue, alreadyDecoded := c.decoder.decodedMap[encodedValue]

	if !alreadyDecoded {
		decodedValue = m.encoding.decode(encodedValue)
		// Invalid lookalikes are overwhelmingly unique identifiers. Caching
		// those empty results grows a large map without avoiding useful work.
		if decodedValue != "" {
			if c.decoder.decodedMap == nil {
				c.decoder.decodedMap = make(map[string]string)
			}
			c.decoder.decodedMap[encodedValue] = decodedValue
		}
	}

	if len(decodedValue) == 0 {
		return
	}

	segment := c.decoder.newSegment(EncodedSegment{
		predecessors: c.predecessors,
		original:     toOriginal(c.predecessors, m.startEnd),
		encoded:      m.startEnd,
		decoded: startEnd{
			m.start + c.decodedShift,
			m.start + c.decodedShift + len(decodedValue),
		},
		decodedValue: decodedValue,
		encodings:    m.encoding.kind,
		depth:        1,
	})

	// Shift decoded start and ends based on size changes
	c.decodedShift += len(decodedValue) - len(encodedValue)

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

	logging.Trace().
		Str("decoder", m.encoding.kind.String()).
		Msgf(
			"segment found: original=%s pos=%s: %q -> %q",
			segment.original,
			segment.encoded,
			encodedValue,
			segment.decodedValue,
		)
}

type decodedBytesSegmentCollector struct {
	decoder      *Decoder
	data         []byte
	predecessors []*EncodedSegment
	decodedShift int
}

func (c *decodedBytesSegmentCollector) add(m encodingMatch) {
	encodedValue := c.data[m.start:m.end]
	decodedValue := m.encoding.decodeBytes(encodedValue)
	if decodedValue == "" {
		return
	}

	segment := c.decoder.newSegment(EncodedSegment{
		predecessors: c.predecessors,
		original:     toOriginal(c.predecessors, m.startEnd),
		encoded:      m.startEnd,
		decoded: startEnd{
			m.start + c.decodedShift,
			m.start + c.decodedShift + len(decodedValue),
		},
		decodedValue: decodedValue,
		encodings:    m.encoding.kind,
		depth:        1,
	})
	c.decodedShift += len(decodedValue) - len(encodedValue)

	if len(segment.predecessors) != 0 {
		segment.depth = 1 + segment.predecessors[0].depth
		for _, predecessor := range segment.predecessors {
			if segment.encoded.overlaps(predecessor.decoded) {
				segment.encodings |= predecessor.encodings
			}
		}
	}

	event := logging.Trace().Str("decoder", m.encoding.kind.String())
	if event.Enabled() {
		event.Msgf(
			"segment found: original=%s pos=%s: %q -> %q",
			segment.original,
			segment.encoded,
			encodedValue,
			segment.decodedValue,
		)
	}
}
