package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsHyperVInstalled(t *testing.T) {
	installed, err := WindowsHyperVInstalled()
	require.Nil(t, err)
	assert.Equal(t, true, installed)
}
