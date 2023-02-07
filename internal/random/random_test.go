package random

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	for i := 1; i < 45; i++ {
		n := Name(i)
		assert.Greater(t, len(n), 0)
		assert.LessOrEqual(t, len(n), i)
	}
}

func TestPkixName(t *testing.T) {
	n := PkixName()
	assert.NotEmpty(t, n.CommonName)
	assert.Len(t, n.Organization, 1)
	assert.NotEmpty(t, n.Organization[0])
	assert.Len(t, n.Locality, 1)
	assert.NotEmpty(t, n.Locality[0])
	assert.Len(t, n.Province, 1)
	assert.NotEmpty(t, n.Province[0])
	assert.Len(t, n.Country, 1)
	assert.NotEmpty(t, n.Country[0])
}
