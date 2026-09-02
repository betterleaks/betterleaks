package tokenizer

import (
	"encoding/binary"
	"hash/fnv"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCounter(t *testing.T) {
	counter, err := New()
	require.NoError(t, err)

	tests := []struct {
		input string
		want  int
	}{
		{input: "", want: 0},
		{input: "MIGRATE_HELM_2TO3", want: 9},
		{input: "linkedinX9qB2mK7pR4zT8", want: 15},
		{input: "this-is-a-long-readable-placeholder-value", want: 7},
		{input: "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5", want: 38},
		{input: "line one\r\nline two\n\nline three", want: 8},
		{input: "<|endoftext|>", want: 7},
		{input: "こんにちは世界", want: 4},
		{input: "🔐 secrets café", want: 5},
		{input: strings.Repeat("a", 1_000), want: 125},
	}
	for _, test := range tests {
		require.Equal(t, test.want, counter.Count(test.input), "input %q", test.input)
	}
}

func TestCounterCompatibility(t *testing.T) {
	counter, err := New()
	require.NoError(t, err)

	inputs := []string{
		"",
		"MIGRATE_HELM_2TO3",
		"linkedinX9qB2mK7pR4zT8",
		"this-is-a-long-readable-placeholder-value",
		"ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5",
		"line one\r\nline two\n\nline three",
		"<|endoftext|>",
		"こんにちは世界",
		"🔐 secrets café",
		strings.Repeat("a", 1_000),
	}

	random := rand.New(rand.NewPCG(0x5eed, 0xc0ffee))
	alphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:+ =\r\n世界🔐é")
	for range 2_000 {
		length := random.IntN(128)
		value := make([]rune, length)
		for i := range value {
			value[i] = alphabet[random.IntN(len(alphabet))]
		}
		inputs = append(inputs, string(value))
	}

	digest := fnv.New64a()
	var encodedCount [8]byte
	for _, input := range inputs {
		binary.LittleEndian.PutUint64(encodedCount[:], uint64(counter.Count(input)))
		_, _ = digest.Write(encodedCount[:])
	}
	// Generated with tiktoken-go v0.1.8. This broad deterministic corpus catches
	// compatibility changes that the readable cases above may not exercise.
	require.Equal(t, uint64(0x5183dc9c07b70cf4), digest.Sum64())
}

func TestDefault(t *testing.T) {
	first, err := Default()
	require.NoError(t, err)
	second, err := Default()
	require.NoError(t, err)
	require.Same(t, first, second)
}

func TestCounterConcurrent(t *testing.T) {
	counter, err := Default()
	require.NoError(t, err)

	for i := range 16 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			for range 100 {
				require.Equal(t, 9, counter.Count("MIGRATE_HELM_2TO3"))
			}
		})
	}
}

var benchmarkTokenCount int

func BenchmarkCounterCount(b *testing.B) {
	counter, err := New()
	require.NoError(b, err)
	input := "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkTokenCount = counter.Count(input)
	}
}
