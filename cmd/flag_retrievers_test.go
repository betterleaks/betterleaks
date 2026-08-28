package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{input: "", want: 0},
		{input: "0", want: 0},
		{input: "250MiB", want: 250 * 1024 * 1024},
		{input: "1GiB", want: 1024 * 1024 * 1024},
		{input: "1GB", want: 1_000_000_000},
		{input: "512kB", want: 512_000},
		{input: "notasize", wantErr: true},
		{input: "12 zettabytes", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSize(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
