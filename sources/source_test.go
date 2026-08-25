package sources

import "testing"

func TestAllocateProviderWorkers(t *testing.T) {
	tests := []struct {
		name                 string
		configured           int
		defaultTargetWorkers int
		singleTarget         bool
		want                 providerWorkerAllocation
	}{
		{
			name:                 "default collection preserves source defaults",
			defaultTargetWorkers: 100,
			want:                 providerWorkerAllocation{TargetWorkers: 100},
		},
		{
			name:                 "default single target preserves nested defaults",
			defaultTargetWorkers: 100,
			singleTarget:         true,
			want:                 providerWorkerAllocation{TargetWorkers: 1},
		},
		{
			name:                 "single target receives full budget",
			configured:           16,
			defaultTargetWorkers: 100,
			singleTarget:         true,
			want:                 providerWorkerAllocation{TargetWorkers: 1, WorkersPerTarget: 16},
		},
		{
			name:                 "four workers",
			configured:           4,
			defaultTargetWorkers: 100,
			want:                 providerWorkerAllocation{TargetWorkers: 1, WorkersPerTarget: 3},
		},
		{
			name:                 "eight workers",
			configured:           8,
			defaultTargetWorkers: 100,
			want:                 providerWorkerAllocation{TargetWorkers: 2, WorkersPerTarget: 3},
		},
		{
			name:                 "sixteen workers",
			configured:           16,
			defaultTargetWorkers: 100,
			want:                 providerWorkerAllocation{TargetWorkers: 4, WorkersPerTarget: 3},
		},
		{
			name:                 "target workers cap at four",
			configured:           32,
			defaultTargetWorkers: 100,
			want:                 providerWorkerAllocation{TargetWorkers: 4, WorkersPerTarget: 7},
		},
		{
			name:                 "small budget keeps both lanes alive",
			configured:           2,
			defaultTargetWorkers: 100,
			want:                 providerWorkerAllocation{TargetWorkers: 1, WorkersPerTarget: 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := allocateProviderWorkers(test.configured, test.defaultTargetWorkers, test.singleTarget)
			if got != test.want {
				t.Fatalf("allocateProviderWorkers(%d, %d, %t) = %+v, want %+v",
					test.configured, test.defaultTargetWorkers, test.singleTarget, got, test.want)
			}
		})
	}
}
