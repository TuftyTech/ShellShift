package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/publish"
)

func params(uri string) map[string]string {
	out := map[string]string{}
	body, _, _ := strings.Cut(uri, "#")
	_, q, ok := strings.Cut(body, "?")
	if !ok {
		return out
	}
	for _, pair := range strings.Split(q, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		if k != "" {
			out[strings.ToLower(k)] = v
		}
	}
	return out
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()

	dropped := map[string]int{}
	added := map[string]int{}
	changed := map[string]int{}
	identical, total := 0, 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res, derr := decode.Decode(line)
		if derr != nil {
			continue
		}
		out, eerr := publish.Encode(res.Node, "x")
		if eerr != nil {
			continue
		}
		total++
		if strings.Split(line, "#")[0] == strings.Split(out, "#")[0] {
			identical++
		}
		before, after := params(line), params(out)
		for k, bv := range before {
			av, present := after[k]
			switch {
			case !present:
				dropped[k]++
			case av != bv:
				changed[k+": "+bv+" -> "+av]++
			}
		}
		for k := range after {
			if _, present := before[k]; !present {
				added[k]++
			}
		}
	}

	show := func(title string, m map[string]int) {
		if len(m) == 0 {
			fmt.Printf("  %s: нет\n", title)
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
		fmt.Printf("  %s:\n", title)
		for _, k := range keys {
			fmt.Printf("    %4d  %s\n", m[k], k)
		}
	}

	fmt.Printf("узлов: %d, побайтово идентичных: %d\n", total, identical)
	show("ПОТЕРЯННЫЕ параметры", dropped)
	show("ДОБАВЛЕННЫЕ параметры", added)
	show("ИЗМЕНЁННЫЕ значения", changed)
}
