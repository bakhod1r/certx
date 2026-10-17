package webserver

import (
	"reflect"
	"testing"
)

func TestWeakProtocols(t *testing.T) {
	cases := []struct {
		kind Kind
		in   []string
		want []string
	}{
		{KindNginx, []string{"TLSv1.2", "TLSv1.3"}, nil},
		{KindNginx, []string{"TLSv1", "TLSv1.1", "TLSv1.2"}, []string{"TLSv1", "TLSv1.1"}},
		{KindApache, []string{"all", "-SSLv3"}, []string{"TLSv1", "TLSv1.1"}},
		{KindApache, []string{"all", "-SSLv3", "-TLSv1", "-TLSv1.1"}, nil},
		{KindApache, []string{"-all", "+TLSv1.2", "+TLSv1.3"}, nil},
		{KindNginx, nil, nil},
	}
	for _, c := range cases {
		if got := WeakProtocols(c.kind, c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("WeakProtocols(%s, %v) = %v, want %v", c.kind, c.in, got, c.want)
		}
	}
}
