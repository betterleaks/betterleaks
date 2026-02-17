package words

import "testing"

func TestMaxMatchLenASCII(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		stopAt int
		want   int
	}{
		{"empty string", "", 0, 0},
		{"shorter than any word", "ab", 0, 0},
		{"no dictionary substring", "zxqjvkbp", 0, 0},
		{"exact word pass", "pass", 0, 4},
		{"password contains 8-char match", "password", 0, 8},
		{"word in middle", "xxwordxx", 0, 4},
		{"aba is 3-char word", "aba", 0, 3},
		{"stopAt 5 with password", "password", 5, 8},
		{"stopAt 5 with short match", "xxwordxx", 5, 4},
		{"case insensitive", "PASSWORD", 0, 8},
		{"mixed case", "PassWord", 0, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Default.MaxMatchLenASCII(tt.input, tt.stopAt)
			if got != tt.want {
				t.Errorf("MaxMatchLenASCII(%q, %d) = %d, want %d",
					tt.input, tt.stopAt, got, tt.want)
			}
		})
	}
}

func TestContainsAnyASCII(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		minLen int
		want   bool
	}{
		{"password has 5+ match", "password", 5, true},
		{"word has no 5+ match", "xxwordxx", 5, false},
		{"word has 3+ match", "xxwordxx", 3, true},
		{"no match", "zxqjvkbp", 3, false},
		{"empty", "", 3, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Default.ContainsAnyASCII(tt.input, tt.minLen)
			if got != tt.want {
				t.Errorf("ContainsAnyASCII(%q, %d) = %v, want %v",
					tt.input, tt.minLen, got, tt.want)
			}
		})
	}
}

func TestMustLoadMatcher(t *testing.T) {
	if Default == nil {
		t.Fatal("Default matcher is nil")
	}
}

var benchMaxLen int

func BenchmarkMaxMatchLenASCII(b *testing.B) {
	cases := []struct {
		name   string
		input  string
		stopAt int
	}{
		{"Short/Hit", "password", 5},
		{"Short/Miss", "zxqjvkbp", 5},
		{"Medium/Hit", "ghaborneacknowledging", 5},
		{"Medium/Miss", "zxqjvkbpwmfltrhndsgcy", 5},
		{"Long/Hit", "understandingpasswordacknowledgement", 5},
		{"Long/Miss", "zxqjvkbpwmfltrhndsgnywcxzqjvkbpwmfltrhn", 5},
		{"NoMatch", "", 5},
		{"StopAt3", "password", 3},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchMaxLen = Default.MaxMatchLenASCII(tc.input, tc.stopAt)
			}
		})
	}
}
